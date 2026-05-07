"""Lumina Threat Intel — Dark-web scraper engine.

Powered by Robin's proven Tor search and scrape modules.
This module provides the same public interface (search_dark_web,
scrape_results) so the orchestrator needs no import changes.
"""
from __future__ import annotations

import logging
import os
import sys
from datetime import datetime
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# ── Robin import path setup ──
_robin_dir = os.path.join(
    os.path.dirname(__file__), os.pardir, os.pardir, "robin",
)
_robin_dir = os.path.normpath(_robin_dir)
if _robin_dir not in sys.path:
    sys.path.insert(0, _robin_dir)

# Import Robin's working modules
from search import get_search_results as _robin_search       # noqa: E402
from search import fetch_search_results as _robin_fetch       # noqa: E402
from search import DEFAULT_SEARCH_ENGINES as _robin_engines   # noqa: E402
from scrape import scrape_multiple as _robin_scrape_multiple  # noqa: E402
from scrape import scrape_single as _robin_scrape_single      # noqa: E402


def search_dark_web(
    queries: list[dict[str, str]],
    max_workers: int = 5,
) -> list[dict[str, str]]:
    """Execute multiple queries across Robin's dark-web search engines.

    Adapts from the Lumina query format [{query, category}] to Robin's
    single-query format and back.

    Args:
        queries: list of {"query": str, "category": str}
        max_workers: thread pool size

    Returns:
        Deduplicated list of {"title", "link", "search_engine", "category"}
    """
    all_results: list[dict[str, str]] = []

    for q in queries:
        query_text = q.get("query", "")
        category = q.get("category", "exploit")

        if not query_text:
            continue

        logger.info(
            "Searching dark web for query: '%s' (category: %s)",
            query_text[:60], category,
        )

        try:
            # Robin's get_search_results returns list of {"title", "link"}
            results = _robin_search(query_text, max_workers=max_workers)

            # Cap results per query to avoid overwhelming the pipeline
            if len(results) > 50:
                results = results[:50]

            for r in results:
                all_results.append({
                    "title": r.get("title", "Untitled"),
                    "link": r.get("link", ""),
                    "search_engine": "Robin-Tor",
                    "category": category,
                })
        except Exception as e:
            logger.error(
                "Robin search failed for query '%s': %s",
                query_text[:60], str(e)[:150],
            )

    # Deduplicate by link
    seen: set[str] = set()
    unique: list[dict[str, str]] = []
    for r in all_results:
        link = r.get("link", "").rstrip("/")
        if link and link not in seen:
            seen.add(link)
            unique.append(r)

    logger.info(
        "Dark web search: %d unique results from %d total across %d queries",
        len(unique), len(all_results), len(queries),
    )
    return unique


def scrape_results(
    search_results: list[dict[str, str]],
    max_workers: int = 5,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> list[dict[str, Any]]:
    """Scrape multiple .onion URLs concurrently using Robin's engine.

    Adapts Robin's scrape_multiple output (dict[url->content]) to the
    list-of-dicts format expected by the orchestrator.

    Args:
        search_results: output from search_dark_web()
        max_workers: thread pool size
        progress_cb: optional (done, total) callback for SSE updates

    Returns:
        List of scrape result dicts with text content.
    """
    if not search_results:
        return []

    # Build lookup: url -> metadata from search results
    url_metadata: dict[str, dict[str, str]] = {}
    robin_input: list[dict[str, str]] = []

    for sr in search_results:
        url = (sr.get("link") or "").strip()
        if not url:
            continue
        url_metadata[url] = {
            "title": sr.get("title", "Untitled"),
            "engine": sr.get("search_engine", ""),
            "category": sr.get("category", ""),
        }
        robin_input.append({
            "link": url,
            "title": sr.get("title", "Untitled"),
        })

    total = len(robin_input)
    logger.info("Scraping %d URLs via Robin engine", total)

    # Robin's scrape_multiple returns dict[url -> content_text]
    scraped_map = _robin_scrape_multiple(robin_input, max_workers=max_workers)

    # Convert to Lumina's expected list format
    results: list[dict[str, Any]] = []
    done = 0

    for url, content in scraped_map.items():
        meta = url_metadata.get(url, {})
        results.append({
            "url": url,
            "title": meta.get("title", "Untitled"),
            "text": content,
            "engine": meta.get("engine", ""),
            "category": meta.get("category", ""),
            "http_status": 200 if content else 0,
            "content_length": len(content) if content else 0,
            "scraped_at": datetime.utcnow().isoformat(),
        })
        done += 1
        if progress_cb:
            progress_cb(done, total)

    # Report progress for any URLs that weren't in the scraped map
    remaining = total - done
    if remaining > 0 and progress_cb:
        progress_cb(total, total)

    logger.info(
        "Scraping complete: %d/%d pages returned content",
        len([r for r in results if r.get("text")]),
        total,
    )
    return results
