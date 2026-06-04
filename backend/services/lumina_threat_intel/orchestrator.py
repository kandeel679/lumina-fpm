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
    AssessedFindingsOutput,
    CategoryRefinementOutput,
    ConsolidatedFindingsOutput,
    QueryGenerationOutput,
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
from .prompts.findings import build_findings_prompt
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


def _generate_queries_batched(
    keywords: dict[str, list[str]],
    requested_categories: list[str],
    max_queries: int = 8,
) -> list[dict[str, str]]:
    """Generate ALL dark-web search queries in a SINGLE structured LLM call.

    Replaces ``_build_search_queries_from_keywords`` (which called Robin's
    ``refine_query`` once per keyword value — 30-50 calls that exhausted the
    Gemini free-tier 5-req/min quota in Step 2 alone). Uses LTI's own
    ``QUERY_GENERATOR_PROMPT`` + ``QueryGenerationOutput`` schema, which were
    already present but previously unused.
    """
    if keywords_are_empty(keywords):
        logger.warning("Keyword bundle empty — no queries generated")
        return []

    keyword_bundle_json = json.dumps(keywords, indent=2)
    prompt = QUERY_GENERATOR_PROMPT.format(keyword_bundle_json=keyword_bundle_json)

    try:
        result = call_llm_structured(prompt, QueryGenerationOutput, tier="fast")
    except (LLMValidationError, LLMProviderError) as e:
        logger.error("Batched query generation failed: %s", str(e))
        return []

    queries: list[dict[str, str]] = []
    seen: set[str] = set()
    for gq in result.queries:
        category = gq.category.value if hasattr(gq.category, "value") else str(gq.category)
        if category not in requested_categories:
            continue
        query_text = (gq.query or "").strip()
        key = query_text.lower()
        if query_text and key not in seen:
            seen.add(key)
            queries.append({"query": query_text, "category": category})
        if len(queries) >= max_queries:
            break

    logger.info(
        "Generated %d search queries in 1 batched LLM call (was 30-50 calls)",
        len(queries),
    )
    return queries


def _filter_results_in_code(
    search_results: list[dict[str, str]],
    queries: list[dict[str, str]],
    top_n: int = 20,
) -> list[dict[str, str]]:
    """Rank and trim search results WITHOUT an LLM call.

    Replaces Robin's ``filter_results`` (1 LLM call that, worse, judged every
    result against ``queries[0]`` only). Scores each result by query-term
    overlap in its title + a small bonus for content-like URLs, then keeps the
    top_n. Pure code → 0 tokens, 0 rate-limit cost.
    """
    if not search_results:
        return []

    terms: set[str] = set()
    for q in queries:
        for tok in (q.get("query") or "").lower().split():
            if len(tok) >= 3:
                terms.add(tok)

    content_markers = ("/product", "/topic", "/thread", "/post", "/cve", "/exploit", "/leak")

    def score(r: dict[str, str]) -> int:
        title = (r.get("title") or "").lower()
        link = (r.get("link") or "").lower()
        s = sum(1 for t in terms if t in title)
        if any(seg in link for seg in content_markers):
            s += 1
        return s

    ranked = sorted(search_results, key=score, reverse=True)
    return ranked[:top_n]


def _build_corpus(
    scrape_data: list[dict[str, Any]],
    max_pages: int = 25,
    max_chars: int = 60000,
) -> str:
    """Assemble ONE token-budgeted corpus from scraped pages for the single
    consolidated Findings call. Each page is labelled with its source so the
    model can cite source_url / page_title accurately.
    """
    blocks: list[str] = []
    total = 0
    for sd in scrape_data:
        text = (sd.get("text") or "").strip()
        if not text:
            continue
        url = sd.get("url", "")
        title = sd.get("title", "")
        block = f"[SOURCE_URL: {url}]\n[PAGE_TITLE: {title}]\n{text}"
        if total + len(block) > max_chars:
            block = block[: max(0, max_chars - total)]
        if not block:
            break
        blocks.append(block)
        total += len(block)
        if len(blocks) >= max_pages or total >= max_chars:
            break
    return "\n\n=====\n\n".join(blocks)


def _build_clean_digest(scrape_data: list[dict[str, Any]], max_items: int = 25) -> str:
    """Build a MODERATION-SAFE digest of dark-web search hits for the LLM.

    Cloud gateways (Gemini, AgentRouter, ...) block raw dark-web page text. So
    we NEVER send raw prose to the cloud LLM. Instead we send only benign
    metadata + code-extracted, DEFANGED indicators (CVE / IP / email) pulled
    from each page. Raw text stays local (used for persistence/correlation only).
    """
    import re
    from urllib.parse import urlparse

    cve_re = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
    ipv4_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    email_re = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

    def _defang(s: str) -> str:
        return s.replace("http", "hxxp").replace(".", "[.]")

    items: list[dict[str, Any]] = []
    for sd in scrape_data:
        text = sd.get("text") or ""
        url = sd.get("url", "")
        title = (sd.get("title") or "")[:180]
        try:
            host = urlparse(url).hostname or ""
        except Exception:
            host = ""
        cves = sorted({m.upper() for m in cve_re.findall(text)})[:10]
        ips = sorted(set(ipv4_re.findall(text)))[:8]
        emails = sorted(set(email_re.findall(text)))[:5]
        items.append({
            "title": title,
            "source": host,
            "url": url,
            "cves": cves,
            "ips": [_defang(x) for x in ips],
            "emails": [_defang(x) for x in emails],
        })
        if len(items) >= max_items:
            break
    return json.dumps(items, indent=1)


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
        # Build marker — appears in celery logs ONLY when the worker has loaded
        # THIS orchestrator. If a scan's logs lack this line, celery_worker is
        # running STALE code (the worker has no --reload): restart it.
        logger.info("LTI orchestrator build=assessment-v2 "
                    "(clean + coverage_note + router-model-report)")
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
            queries = _generate_queries_batched(keywords, requested_categories)
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
            
            # Check Tor proxy connection first to fail fast
            import socket
            proxy_host = os.environ.get("LTI_TOR_SOCKS_HOST", "127.0.0.1")
            proxy_port = int(os.environ.get("LTI_TOR_SOCKS_PORT", 9050))
            try:
                with socket.create_connection((proxy_host, proxy_port), timeout=5):
                    pass
            except OSError as e:
                error_msg = f"Failed to connect to Tor proxy at {proxy_host}:{proxy_port}: {e}"
                logger.error(error_msg)
                _log_error(report, "search_dark_web", error_msg)
                raise Exception(error_msg)

            search_results = search_dark_web(queries, max_workers=5)
            logger.info("Search returned %d results", len(search_results))

            # Cap total search results
            if len(search_results) > 100:
                search_results = search_results[:100]

            sse_publisher.emit(report.id, "search_complete", {
                "results_count": len(search_results),
            })

            # ── Step 4: Filter results in code (no LLM call) ──
            if search_results:
                before = len(search_results)
                search_results = _filter_results_in_code(
                    search_results, queries, top_n=20,
                )
                logger.info(
                    "Step 4: Filtered %d -> %d results in code (no LLM call)",
                    before, len(search_results),
                )

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

            # ── Step 6+7: ONE consolidated Findings call ──
            # Replaces Robin's generic narrative + the 5 per-category refiners
            # (6 LLM calls -> 1). The customer's firewall fingerprint is injected
            # so the model reasons relevance natively instead of returning
            # generic dark-web OSINT. Corpus is token-budgeted to fit one call.
            logger.info("Step 6+7: Consolidated Findings extraction (1 LLM call)")
            # Corpus mode (env LTI_CORPUS_MODE):
            #   "digest"   = moderation-safe metadata + defanged IOCs (default;
            #                for restrictive gateways like Gemini/AgentRouter)
            #   "excerpts" = Robin-style truncated REAL page text (for permissive
            #                APIs like DeepSeek/Ollama) -> richer, dedicated reports
            if os.getenv("LTI_CORPUS_MODE", "digest").lower() == "excerpts":
                corpus = _build_corpus(scrape_data, max_pages=25, max_chars=60000)
            else:
                corpus = _build_clean_digest(scrape_data, max_items=25)
            keyword_json = json.dumps(keywords, indent=2)

            if not corpus.strip():
                logger.warning("Empty corpus — no findings to extract")
                report.narrative_summary = (
                    "No dark-web content was retrieved for analysis."
                )
            else:
                findings_prompt = build_findings_prompt(
                    firewall_context_json=keyword_json,
                    requested_categories=requested_categories,
                    scraped_text=corpus,
                )
                try:
                    result = call_llm_structured(
                        findings_prompt, AssessedFindingsOutput, tier="strong",
                    )
                    report.narrative_summary = result.narrative_summary or ""
                    report.coverage_note = result.coverage_note or ""
                    all_findings = [f.model_dump(mode="json") for f in result.findings]
                    # Derive the legacy severity column from criticality (info -> low)
                    for fd in all_findings:
                        crit = fd.get("criticality") or "low"
                        fd["severity"] = "low" if crit == "info" else crit
                    # Validate IOCs against source (no hallucinations)
                    all_findings = _validate_iocs_in_source(all_findings)
                except (LLMValidationError, LLMProviderError) as e:
                    logger.error("Consolidated findings extraction failed: %s", str(e))
                    _log_error(report, "findings", str(e))
                    report.narrative_summary = "Findings extraction failed."
                    had_partial_failures = True
                    all_findings = []

                sse_publisher.emit(report.id, "findings_extracted", {
                    "count": len(all_findings),
                })

        # ── Clearnet seed findings (deterministic, no LLM / no Tor) ──
        # Authoritative CVE/KEV data scoped to the customer's firewall vendors;
        # reliable even when Tor is flaky, and free against the LLM budget.
        darkweb_count = len(all_findings)
        clearnet_count = 0
        try:
            from .clearnet_intel import fetch_clearnet_findings
            clearnet_findings = fetch_clearnet_findings(db, device_ids=device_ids)
            if clearnet_findings:
                clearnet_count = len(clearnet_findings)
                all_findings.extend(clearnet_findings)
                logger.info("Merged %d clearnet (CISA KEV + NVD) findings", clearnet_count)
                sse_publisher.emit(report.id, "clearnet_merged", {"count": clearnet_count})
        except Exception as e:
            logger.error("Clearnet intel failed: %s", str(e))
            _log_error(report, "clearnet", str(e))

        # ── Step 8: Dedupe IOCs ──
        all_findings = _dedupe_iocs(all_findings)

        # ── Step 9: Correlate ──
        logger.info("Step 9: Correlating against firewall inventory")
        all_findings = correlate_findings(db, all_findings, device_ids=device_ids)
        sse_publisher.emit(report.id, "correlation_complete", {})

        # Clean state (assessment model): clean = NO finding reached relevance
        # band medium or high (computed AFTER the correlator's hybrid adjustment).
        report.clean = not any(
            f.get("relevance_band") in ("medium", "high") for f in all_findings
        )

        # Guarantee a non-null coverage_note (the "this FW is clean — here's what
        # we checked" UX). Prefer the LLM's note; else synthesize a deterministic
        # summary of what was actually searched / ruled out.
        if not (report.coverage_note or "").strip():
            raised = sum(
                1 for f in all_findings
                if f.get("relevance_band") in ("medium", "high")
            )
            report.coverage_note = (
                f"Searched {report.queries_generated_count or 0} dark-web queries; "
                f"scraped {report.onion_pages_scraped_count or 0} onion pages; "
                f"cross-checked clearnet feeds (CISA KEV, NVD) scoped to the "
                f"customer's firewall vendors. "
                + (
                    "No item reached medium+ relevance to the monitored firewalls."
                    if report.clean
                    else f"{raised} item(s) reached medium+ relevance — see findings."
                )
            )

        # Diagnostics (visible in celery logs): per-source counts and the
        # relevance-band distribution that drove `clean`.
        from collections import Counter
        _bands = Counter(f.get("relevance_band") for f in all_findings)
        logger.info(
            "Assessment: darkweb=%d clearnet=%d total=%d clean=%s bands=%s",
            darkweb_count, clearnet_count, len(all_findings),
            report.clean, dict(_bands),
        )

        # ── Step 10: Diff ──
        logger.info("Step 10: Diff tracking")
        all_findings = mark_new_findings(db, report.id, all_findings)

        # ── Step 11: Persist findings and IOCs ──
        logger.info("Step 11: Persisting %d findings", len(all_findings))
        for fd in all_findings:
            # Info-criticality findings appear in the narrative but are NOT
            # persisted as finding rows (assessment-model decision).
            if fd.get("criticality") == "info":
                continue
            source = fd.get("source", {})
            finding_row = ThreatIntelFinding(
                report_id=report.id,
                category=fd.get("category", "exploit"),
                severity=fd.get("severity", "low"),
                criticality=fd.get("criticality"),
                relevance_score=fd.get("relevance_score"),
                relevance_band=fd.get("relevance_band"),
                relevance_reason=fd.get("relevance_reason"),
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
        # Report the model the router ACTUALLY used (the configured ROBIN_MODEL
        # env is only the legacy default and may not be what ran).
        try:
            from .model_router import last_model_used
            report.llm_model_name = last_model_used() or f"robin/{robin_model}"
        except Exception:
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
