"""Pipeline orchestrator — runs the full threat-intel scan pipeline.

Powered by Robin's dark-web engine for search, scrape, and LLM operations.
Uses Lumina's API/DB layer for persistence, correlation, and diff tracking.

Sequence:
  1. Extract keywords from Lumina DB
  2. Generate dark-web queries via Robin's LLM (refine_query)
  3. Search dark web via Robin's Tor engine (get_search_results)
  4. Filter search results via Robin's LLM (filter_results)
  5. Scrape .onion pages via Robin's scraper (scrape_multiple)
  6. Generate narrative summary via Robin's LLM (generate_summary)
  7. Extract structured findings via LLM refiner prompts
  8. Validate IOCs against source text (no hallucinations)
  9. Deduplicate IOCs
  10. Correlate against firewall rules/devices
  11. Diff vs previous scans
  12. Persist everything to DB
"""
from __future__ import annotations

import json
import logging
import os
import sys
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
    ScanStatus,
    ThreatCategory,
    TriggerType,
)
from .keyword_extractor import extract_keywords, keywords_are_empty
from .correlator import correlate_findings
from .diff_tracker import mark_new_findings
from .llm_client import call_llm_structured, call_llm_text, get_robin_model_name
from .prompts.query_generator import QUERY_GENERATOR_PROMPT
from .prompts.refiners import build_refiner_prompt
from .prompts.shared import SHARED_PREAMBLE
from .scraper.engine import search_dark_web, scrape_results
from .stream import sse_publisher
from .exceptions import LLMValidationError, LLMProviderError

# ── Robin imports for direct LLM operations ──
_robin_dir = os.path.normpath(
    os.path.join(os.path.dirname(__file__), os.pardir, "robin")
)
if _robin_dir not in sys.path:
    sys.path.insert(0, _robin_dir)

from llm import (                          # noqa: E402
    get_llm as _robin_get_llm,
    refine_query as _robin_refine_query,
    filter_results as _robin_filter_results,
    generate_summary as _robin_generate_summary,
)

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


def _build_search_queries_from_keywords(
    llm,
    keywords: dict[str, list[str]],
    requested_categories: list[str],
) -> list[dict[str, str]]:
    """Convert keyword bundle into dark-web search queries.

    Uses Robin's refine_query to produce optimal search terms from
    each keyword group, then tags them with a category.
    """
    queries: list[dict[str, str]] = []
    seen_queries: set[str] = set()

    # Map keyword types to threat categories
    keyword_category_map = {
        "firmwares": "exploit",
        "vendors_models": "exploit",
        "cves": "exploit",
        "org_domains": "credential",
    }

    for key, values in keywords.items():
        if not values:
            continue

        category = keyword_category_map.get(key, "exploit")
        if category not in requested_categories:
            continue

        for value in values[:10]:  # Cap per keyword group
            try:
                refined = _robin_refine_query(llm, value)
                refined = refined.strip()
                if refined and refined.lower() not in seen_queries:
                    seen_queries.add(refined.lower())
                    queries.append({
                        "query": refined,
                        "category": category,
                    })
            except Exception as e:
                logger.warning(
                    "Failed to refine query for '%s': %s",
                    value[:40], str(e)[:100],
                )

    # Also generate category-specific queries if we have org_domains
    org_domains = keywords.get("org_domains", [])
    firmwares = keywords.get("firmwares", [])
    vendors = keywords.get("vendors_models", [])

    # Ransomware queries from org domains
    if "ransomware" in requested_categories:
        for domain in org_domains[:5]:
            try:
                refined = _robin_refine_query(
                    llm, f"{domain} ransomware leak"
                )
                refined = refined.strip()
                if refined and refined.lower() not in seen_queries:
                    seen_queries.add(refined.lower())
                    queries.append({"query": refined, "category": "ransomware"})
            except Exception:
                pass

    # IAB queries from vendors/firmwares
    if "iab" in requested_categories:
        for vendor in vendors[:5]:
            try:
                refined = _robin_refine_query(
                    llm, f"{vendor} access sale firewall"
                )
                refined = refined.strip()
                if refined and refined.lower() not in seen_queries:
                    seen_queries.add(refined.lower())
                    queries.append({"query": refined, "category": "iab"})
            except Exception:
                pass

    # C2 queries from org domains
    if "c2" in requested_categories:
        for domain in org_domains[:3]:
            try:
                refined = _robin_refine_query(
                    llm, f"{domain} C2 malware botnet"
                )
                refined = refined.strip()
                if refined and refined.lower() not in seen_queries:
                    seen_queries.add(refined.lower())
                    queries.append({"query": refined, "category": "c2"})
            except Exception:
                pass

    logger.info("Generated %d search queries from keywords", len(queries))
    return queries


def run_scan(
    db: Session,
    trigger_type: str = "manual",
    admin_id: Optional[int] = None,
    requested_categories: Optional[list[str]] = None,
    device_ids: Optional[list[int]] = None,
    report: Optional[ThreatIntelReport] = None,
) -> ThreatIntelReport:
    """Execute the full threat-intel scan pipeline.

    This is designed to run as a background task. It creates and persists
    a ThreatIntelReport, emitting SSE events throughout.

    Now powered by Robin's engine for search, scrape, and LLM operations.

    Args:
        device_ids: Optional list of device IDs to scope the scan to.
                    If None or empty, all devices are included.
    """
    if requested_categories is None:
        requested_categories = [c.value for c in ThreatCategory]

    # Normalize empty list to None for consistent handling
    if device_ids is not None and len(device_ids) == 0:
        device_ids = None

    # Use the pre-created report if provided (API path), otherwise create one
    if report is None:
        report = ThreatIntelReport(
            trigger_type=trigger_type,
            triggered_by_admin_id=admin_id,
            status="running",
            scan_started_at=datetime.utcnow(),
            scanned_device_ids=device_ids,
        )
        db.add(report)
        db.commit()
        db.refresh(report)

    sse_publisher.emit(report.id, "scan_started", {
        "report_id": report.id,
        "device_ids": device_ids,
    })
    start_time = time.time()
    had_partial_failures = False
    all_findings: list[dict[str, Any]] = []

    try:
        # ── Initialize Robin's LLM ──
        logger.info("Initializing Robin LLM engine")
        robin_model = get_robin_model_name()
        try:
            llm = _robin_get_llm(robin_model)
        except Exception as e:
            logger.error("Failed to initialize Robin LLM: %s", str(e))
            _log_error(report, "llm_init", str(e))
            raise

        # ── Step 1: Extract keywords ──
        logger.info("Step 1: Extracting keywords from Lumina DB")
        keywords = extract_keywords(db, device_ids=device_ids)
        report.input_keywords = keywords
        sse_publisher.emit(report.id, "keywords_extracted", {
            "firmwares": len(keywords.get("firmwares", [])),
            "vendors_models": len(keywords.get("vendors_models", [])),
            "cves": len(keywords.get("cves", [])),
            "org_domains": len(keywords.get("org_domains", [])),
        })

        if keywords_are_empty(keywords):
            logger.warning("No keywords found in DB — scan will produce limited results")

        # ── Step 2: Generate dark-web queries via Robin's LLM ──
        logger.info("Step 2: Generating dark-web queries via Robin's refine_query")
        try:
            queries = _build_search_queries_from_keywords(
                llm, keywords, requested_categories,
            )
        except Exception as e:
            logger.error("Query generation failed: %s", str(e))
            _log_error(report, "query_generation", str(e))
            had_partial_failures = True
            queries = []

        report.queries_generated_count = len(queries)
        sse_publisher.emit(report.id, "queries_generated", {"count": len(queries)})

        if not queries:
            logger.warning("No queries generated — skipping search/scrape")
        else:
            # ── Step 3: Search dark web via Robin's Tor engine ──
            logger.info("Step 3: Searching %d queries across dark web via Robin", len(queries))
            search_results = search_dark_web(queries, max_workers=5)
            logger.info("Search returned %d results", len(search_results))

            # Cap total search results
            if len(search_results) > 100:
                search_results = search_results[:100]

            sse_publisher.emit(report.id, "search_complete", {
                "results_count": len(search_results),
            })

            # ── Step 4: Filter results via Robin's LLM ──
            if search_results:
                logger.info("Step 4: Filtering %d results via Robin's LLM", len(search_results))
                try:
                    # Robin's filter expects list of {"title", "link"} dicts
                    # and a query string. Use the first query as the filter query.
                    filter_query = queries[0]["query"]
                    filtered = _robin_filter_results(llm, filter_query, search_results)
                    if filtered:
                        search_results = filtered
                        logger.info("Filtered to %d results", len(search_results))
                except Exception as e:
                    logger.warning(
                        "Robin filter_results failed, using unfiltered: %s",
                        str(e)[:150],
                    )
                    _log_error(report, "filter_results", str(e))

            # ── Step 5: Scrape onion pages via Robin's engine ──
            def scrape_progress(done: int, total: int) -> None:
                sse_publisher.emit(report.id, "scraping_progress", {
                    "done": done, "total": total,
                })

            logger.info("Step 5: Scraping %d results via Robin", len(search_results))
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

            sse_publisher.emit(report.id, "scraping_complete", {
                "pages_scraped": len(scrape_data),
            })

            # ── Step 6: Generate narrative summary via Robin's LLM ──
            logger.info("Step 6: Generating narrative summary via Robin")
            try:
                # Build content dict for Robin: {url: text}
                robin_content = {}
                for sd in scrape_data:
                    url = sd.get("url", "")
                    text = sd.get("text", "")
                    if url and text:
                        robin_content[url] = text

                # Use first query as the main investigation query
                main_query = queries[0]["query"] if queries else "threat intelligence"

                narrative = _robin_generate_summary(
                    llm,
                    main_query,
                    robin_content,
                    preset="threat_intel",
                    custom_instructions="",
                )
                report.narrative_summary = narrative
            except Exception as e:
                logger.error("Narrative generation failed: %s", str(e))
                _log_error(report, "narrative", str(e))
                report.narrative_summary = "Narrative generation failed."
                had_partial_failures = True

            # ── Step 7: Extract structured findings via LLM refiner prompts ──
            logger.info("Step 7: Refining findings per category")
            keyword_json = json.dumps(keywords, indent=2)

            for cat in requested_categories:
                # Filter scrape data relevant to this category
                cat_texts = [
                    sd.get("text", "")
                    for sd in scrape_data
                    if sd.get("category") == cat and sd.get("text")
                ]

                if not cat_texts:
                    # If no category-specific data, use all scrape data
                    # (Robin doesn't tag by category during search)
                    cat_texts = [
                        sd.get("text", "")
                        for sd in scrape_data
                        if sd.get("text")
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

        # ── Step 8: Dedupe IOCs ──
        all_findings = _dedupe_iocs(all_findings)

        # ── Step 9: Correlate ──
        logger.info("Step 9: Correlating against firewall inventory")
        all_findings = correlate_findings(db, all_findings, device_ids=device_ids)
        sse_publisher.emit(report.id, "correlation_complete", {})

        # ── Step 10: Diff ──
        logger.info("Step 10: Diff tracking")
        all_findings = mark_new_findings(db, report.id, all_findings)

        # ── Step 11: Persist findings and IOCs ──
        logger.info("Step 11: Persisting %d findings", len(all_findings))
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
        report.llm_model_name = f"robin/{robin_model}"

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
