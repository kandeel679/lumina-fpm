"""Pipeline orchestrator — runs the full threat-intel scan pipeline.

Sequence:
  1. Extract keywords from Lumina DB
  2. Generate dark-web queries via LLM
  3. Search + scrape via Tor
  4. Refine per category via LLM (5 parallel calls)
  5. Validate IOCs against source text (no hallucinations)
  6. Deduplicate IOCs
  7. Correlate against firewall rules/devices
  8. Diff vs previous scans
  9. Generate narrative summary
  10. Persist everything to DB
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime
from typing import Any, Optional

from sqlalchemy.orm import Session

from .db_models import (
    ThreatIntelFinding,
    ThreatIntelIOC,
    ThreatIntelRawScrape,
    ThreatIntelReport,
)
from .schemas import (
    CategoryRefinementOutput,
    QueryGenerationOutput,
    ReportNarrative,
    ScanStatus,
    ThreatCategory,
    TriggerType,
)
from .keyword_extractor import extract_keywords, keywords_are_empty
from .correlator import correlate_findings
from .diff_tracker import mark_new_findings
from .llm_client import call_llm_structured, call_llm_text
from .prompts.query_generator import QUERY_GENERATOR_PROMPT
from .prompts.refiners import build_refiner_prompt
from .prompts.shared import SHARED_PREAMBLE
from .scraper.engine import search_dark_web, scrape_results
from .stream import sse_publisher
from .exceptions import LLMValidationError, LLMProviderError

logger = logging.getLogger(__name__)


def _log_error(report: ThreatIntelReport, stage: str, error_msg: str) -> None:
    """Append an error entry to the report's error_log."""
    if report.error_log is None:
        report.error_log = []
    report.error_log.append({
        "stage": stage,
        "error_msg": str(error_msg)[:500],
        "ts": datetime.utcnow().isoformat(),
    })


def _validate_iocs_in_source(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Post-LLM validator: drop any IOC whose value is not a substring
    of the finding's source.raw_excerpt (case-insensitive). Constraint C3."""
    for finding in findings:
        source = finding.get("source", {})
        raw_excerpt = (source.get("raw_excerpt") or "").lower()
        if not raw_excerpt:
            continue

        original_iocs = finding.get("iocs", [])
        valid_iocs = []
        for ioc in original_iocs:
            val = (ioc.get("value") or "").strip().lower()
            if val and val in raw_excerpt:
                valid_iocs.append(ioc)
            else:
                logger.warning(
                    "Dropped hallucinated IOC '%s' not found in source excerpt",
                    ioc.get("value", "")[:60],
                )

        finding["iocs"] = valid_iocs

    return findings


def _dedupe_iocs(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove duplicate IOCs within each finding."""
    for finding in findings:
        seen: set[str] = set()
        unique_iocs = []
        for ioc in finding.get("iocs", []):
            key = f"{ioc.get('type', '')}:{ioc.get('value', '')}".lower()
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)
        finding["iocs"] = unique_iocs
    return findings


def _compute_stats(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute aggregate stats for the report."""
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    total_iocs = 0

    for f in findings:
        sev = f.get("severity", "low")
        cat = f.get("category", "exploit")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_category[cat] = by_category.get(cat, 0) + 1
        total_iocs += len(f.get("iocs", []))

    correlated = sum(
        1 for f in findings
        if f.get("matched_rule_ids") or f.get("matched_device_ids")
    )

    return {
        "total_findings": len(findings),
        "by_severity": by_severity,
        "by_category": by_category,
        "total_iocs": total_iocs,
        "correlated_rules": correlated,
    }


def run_scan(
    db: Session,
    trigger_type: str = "manual",
    admin_id: Optional[int] = None,
    requested_categories: Optional[list[str]] = None,
    report: Optional[ThreatIntelReport] = None,
) -> ThreatIntelReport:
    """Execute the full threat-intel scan pipeline.

    This is designed to run as a background task. It creates and persists
    a ThreatIntelReport, emitting SSE events throughout.
    """
    if requested_categories is None:
        requested_categories = [c.value for c in ThreatCategory]

    # Use the pre-created report if provided (API path), otherwise create one
    if report is None:
        report = ThreatIntelReport(
            trigger_type=trigger_type,
            triggered_by_admin_id=admin_id,
            status="running",
            scan_started_at=datetime.utcnow(),
        )
        db.add(report)
        db.commit()
        db.refresh(report)

    sse_publisher.emit(report.id, "scan_started", {"report_id": report.id})
    start_time = time.time()
    had_partial_failures = False
    all_findings: list[dict[str, Any]] = []

    try:
        # ── Step 1: Extract keywords ──
        logger.info("Step 1: Extracting keywords from Lumina DB")
        keywords = extract_keywords(db)
        report.input_keywords = keywords
        sse_publisher.emit(report.id, "keywords_extracted", {
            "firmwares": len(keywords.get("firmwares", [])),
            "vendors_models": len(keywords.get("vendors_models", [])),
            "cves": len(keywords.get("cves", [])),
            "org_domains": len(keywords.get("org_domains", [])),
        })

        if keywords_are_empty(keywords):
            logger.warning("No keywords found in DB — scan will produce limited results")

        # ── Step 2: Generate dark-web queries ──
        logger.info("Step 2: Generating dark-web queries via LLM")
        keyword_json = json.dumps(keywords, indent=2)
        query_prompt = QUERY_GENERATOR_PROMPT.format(keyword_bundle_json=keyword_json)

        try:
            query_output = call_llm_structured(query_prompt, QueryGenerationOutput)
            queries = [
                {"query": q.query, "category": q.category.value}
                for q in query_output.queries
                if q.category.value in requested_categories
            ]
        except (LLMValidationError, LLMProviderError) as e:
            logger.error("Query generation failed: %s", str(e))
            _log_error(report, "query_generation", str(e))
            had_partial_failures = True
            queries = []

        report.queries_generated_count = len(queries)
        sse_publisher.emit(report.id, "queries_generated", {"count": len(queries)})

        if not queries:
            logger.warning("No queries generated — skipping search/scrape")
        else:
            # ── Step 3: Search + scrape ──
            logger.info("Step 3: Searching %d queries across dark web", len(queries))
            search_results = search_dark_web(queries, max_workers=5)

            def scrape_progress(done: int, total: int) -> None:
                sse_publisher.emit(report.id, "scraping_progress", {
                    "done": done, "total": total,
                })

            logger.info("Step 3b: Scraping %d results", len(search_results))
            scrape_data = scrape_results(
                search_results,
                max_workers=5,
                progress_cb=scrape_progress,
            )
            report.onion_pages_scraped_count = len(scrape_data)

            # Persist raw scrapes (7-day retention)
            for sd in scrape_data:
                raw_scrape = ThreatIntelRawScrape(
                    report_id=report.id,
                    onion_url=sd.get("url"),
                    search_engine=sd.get("engine"),
                    scraped_at=datetime.utcnow(),
                    http_status=sd.get("http_status"),
                    content_length=sd.get("content_length"),
                    raw_text=sd.get("text", "")[:10000],
                )
                db.add(raw_scrape)
            db.commit()

            # ── Step 4: Refine per category ──
            logger.info("Step 4: Refining findings per category")
            for cat in requested_categories:
                # Filter scrape data relevant to this category
                cat_texts = [
                    sd.get("text", "")
                    for sd in scrape_data
                    if sd.get("category") == cat and sd.get("text")
                ]

                if not cat_texts:
                    sse_publisher.emit(report.id, "category_refined", {
                        "category": cat, "count": 0,
                    })
                    continue

                combined_text = "\n\n---\n\n".join(cat_texts[:20])  # Cap input size
                refiner_prompt = build_refiner_prompt(cat, keyword_json, combined_text)

                try:
                    refinement = call_llm_structured(
                        refiner_prompt, CategoryRefinementOutput,
                    )
                    cat_findings = [f.model_dump() for f in refinement.findings]
                except (LLMValidationError, LLMProviderError) as e:
                    logger.error("Refiner failed for category %s: %s", cat, str(e))
                    _log_error(report, f"refiner_{cat}", str(e))
                    had_partial_failures = True
                    cat_findings = []

                # Validate IOCs against source (C3)
                cat_findings = _validate_iocs_in_source(cat_findings)

                sse_publisher.emit(report.id, "category_refined", {
                    "category": cat, "count": len(cat_findings),
                })
                all_findings.extend(cat_findings)

        # ── Step 5: Dedupe IOCs ──
        all_findings = _dedupe_iocs(all_findings)

        # ── Step 6: Correlate ──
        logger.info("Step 6: Correlating against firewall inventory")
        all_findings = correlate_findings(db, all_findings)
        sse_publisher.emit(report.id, "correlation_complete", {})

        # ── Step 7: Diff ──
        logger.info("Step 7: Diff tracking")
        all_findings = mark_new_findings(db, report.id, all_findings)

        # ── Step 8: Narrative summary ──
        logger.info("Step 8: Generating narrative summary")
        try:
            narrative_prompt = (
                SHARED_PREAMBLE
                + "\n\nTASK: Write a 3-5 paragraph executive summary (markdown) "
                "of the following threat intelligence findings. Focus on the most "
                "critical findings, their potential impact on the customer's firewall "
                "infrastructure, and recommended immediate actions.\n\n"
                "FINDINGS:\n" + json.dumps(all_findings[:50], indent=2, default=str)
                + "\n\nKEYWORDS:\n" + keyword_json
                + "\n\nOutput ONLY the markdown narrative. No JSON wrapper."
            )
            narrative_text = call_llm_text(narrative_prompt)
            report.narrative_summary = narrative_text
        except Exception as e:
            logger.error("Narrative generation failed: %s", str(e))
            _log_error(report, "narrative", str(e))
            report.narrative_summary = "Narrative generation failed."
            had_partial_failures = True

        # ── Step 9: Persist findings and IOCs ──
        logger.info("Step 9: Persisting %d findings", len(all_findings))
        for fd in all_findings:
            source = fd.get("source", {})
            finding_row = ThreatIntelFinding(
                report_id=report.id,
                category=fd.get("category", "exploit"),
                severity=fd.get("severity", "low"),
                confidence=fd.get("confidence", 0),
                title=fd.get("title", "Untitled")[:512],
                description=fd.get("description"),
                recommended_actions=fd.get("recommended_actions"),
                tags=fd.get("tags"),
                source_onion_url=source.get("onion_url"),
                source_search_engine=source.get("search_engine"),
                source_scraped_at=None,
                source_raw_excerpt=(source.get("raw_excerpt") or "")[:500],
                source_page_title=source.get("page_title"),
                source_marketplace_or_forum=source.get("marketplace_or_forum"),
                matched_rule_ids=fd.get("matched_rule_ids"),
                matched_device_ids=fd.get("matched_device_ids"),
                correlation_match_reason=fd.get("correlation_match_reason"),
                is_new_since_last_scan=fd.get("is_new_since_last_scan"),
                first_seen_in_scan_id=fd.get("first_seen_in_scan_id"),
                finding_hash=fd.get("finding_hash"),
                parse_error=fd.get("parse_error", False),
            )
            db.add(finding_row)
            db.flush()  # Get the finding ID

            for ioc in fd.get("iocs", []):
                ioc_row = ThreatIntelIOC(
                    finding_id=finding_row.id,
                    ioc_type=ioc.get("type", "domain"),
                    ioc_value=(ioc.get("value") or "")[:2048],
                )
                db.add(ioc_row)

        # Finalize report
        report.stats = _compute_stats(all_findings)
        report.status = "completed" if not had_partial_failures else "partial"
        report.llm_model_name = f"{__import__('os').getenv('LTI_LLM_PROVIDER', 'gemini')}/{__import__('os').getenv('LTI_LLM_MODEL', 'gemini-2.5-flash')}"

        sse_publisher.emit(report.id, "done", {"report_id": report.id})

    except Exception as e:
        logger.exception("Scan pipeline failed: %s", str(e))
        report.status = "failed"
        _log_error(report, "orchestrator", str(e))
        sse_publisher.emit(report.id, "failed", {"error": str(e)[:200]})

    finally:
        report.scan_completed_at = datetime.utcnow()
        report.scan_duration_seconds = int(time.time() - start_time)
        db.commit()
        logger.info(
            "Scan %d finished with status=%s in %ds (%d findings)",
            report.id,
            report.status,
            report.scan_duration_seconds,
            len(all_findings),
        )

    return report
