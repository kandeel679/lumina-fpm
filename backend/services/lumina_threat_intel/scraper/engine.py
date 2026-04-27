"""Lumina Threat Intel — Dark-web scraper engine.

Searches 16 dark-web search engines via Tor and scrapes .onion pages
for threat intelligence relevant to the customer's firewall inventory.
"""
from __future__ import annotations

import logging
import os
import re
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Callable, Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# ── Configuration ──
TOR_SOCKS_HOST = os.getenv("LTI_TOR_SOCKS_HOST", "127.0.0.1")
TOR_SOCKS_PORT = int(os.getenv("LTI_TOR_SOCKS_PORT", "9050"))
PAGE_TIMEOUT = int(os.getenv("LTI_SCRAPE_PAGE_TIMEOUT_SECONDS", "60"))
TOTAL_TIMEOUT = int(os.getenv("LTI_SCAN_TOTAL_TIMEOUT_SECONDS", "900"))

MAX_DOWNLOAD_BYTES = 1_000_000
MAX_EXTRACTED_TEXT_CHARS = 50_000
MAX_RETURN_CHARS = 2_000
ALLOWED_CONTENT_TYPES = ("text/html", "application/xhtml+xml", "text/plain")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:137.0) Gecko/20100101 Firefox/137.0",
]

# ── Dark-Web Search Engines ──
SEARCH_ENGINES = [
    {"name": "Ahmia", "url": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={query}"},
    {"name": "OnionLand", "url": "http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={query}"},
    {"name": "Torgle", "url": "http://iy3544gmoeclh5de6gez2256v6pjh4omhpqdh2wpeeppjtvqmjhkfwad.onion/torgle/?query={query}"},
    {"name": "Amnesia", "url": "http://amnesia7u5odx5xbwtpnqk3edybgud5bmiagu75bnqx2crntw5kry7ad.onion/search?query={query}"},
    {"name": "Kaizer", "url": "http://kaizerwfvp5gxu6cppibp7jhcqptavq3iqef66wbxenh6a2fklibdvid.onion/search?q={query}"},
    {"name": "Anima", "url": "http://anima4ffe27xmakwnseih3ic2y7y3l6e7fucwk4oerdn4odf7k74tbid.onion/search?q={query}"},
    {"name": "Tornado", "url": "http://tornadoxn3viscgz647shlysdy7ea5zqzwda7hierekeuokh5eh5b3qd.onion/search?q={query}"},
    {"name": "TorNet", "url": "http://tornetupfu7gcgidt33ftnungxzyfq2pygui5qdoyss34xbgx2qruzid.onion/search?q={query}"},
    {"name": "Torland", "url": "http://torlbmqwtudkorme6prgfpmsnile7ug2zm4u3ejpcncxuhpu4k2j4kyd.onion/index.php?a=search&q={query}"},
    {"name": "Find Tor", "url": "http://findtorroveq5wdnipkaojfpqulxnkhblymc7aramjzajcvpptd4rjqd.onion/search?q={query}"},
    {"name": "Excavator", "url": "http://2fd6cemt4gmccflhm6imvdfvli3nf7zn6rfrwpsy7uhxrgbypvwf5fad.onion/search?query={query}"},
    {"name": "Onionway", "url": "http://oniwayzz74cv2puhsgx4dpjwieww4wdphsydqvf5q7eyz4myjvyw26ad.onion/search.php?s={query}"},
    {"name": "Tor66", "url": "http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/search?q={query}"},
    {"name": "OSS", "url": "http://3fzh7yuupdfyjhwt3ugzqqof6ulbcl27ecev33knxe3u7goi3vfn2qqd.onion/oss/index.php?search={query}"},
    {"name": "Torgol", "url": "http://torgolnpeouim56dykfob6jh5r2ps2j73enc42s2um4ufob3ny4fcdyd.onion/?q={query}"},
    {"name": "The Deep Searches", "url": "http://searchgf7gdtauh7bhnbyed4ivxqmuoat3nm6zfrg3ymkq6mtnpye3ad.onion/search?q={query}"},
]

_thread_local = threading.local()


# ── Session Management ──

def _build_session(use_tor: bool = True) -> requests.Session:
    """Build a requests session with retry logic and optional Tor proxy."""
    session = requests.Session()
    retry = Retry(
        total=3,
        read=3,
        connect=3,
        backoff_factor=0.3,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=frozenset(["GET", "HEAD"]),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    if use_tor:
        proxy = f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}"
        session.proxies = {"http": proxy, "https": proxy}

    return session


def _get_session(use_tor: bool = True) -> requests.Session:
    """Thread-local session caching."""
    key = "tor_session" if use_tor else "direct_session"
    if not hasattr(_thread_local, key):
        setattr(_thread_local, key, _build_session(use_tor=use_tor))
    return getattr(_thread_local, key)


# ── Search ──

def _search_single_engine(
    engine_url: str,
    engine_name: str,
    query: str,
) -> list[dict[str, str]]:
    """Search a single dark-web engine via Tor and return results."""
    url = engine_url.format(query=query.replace(" ", "+"))
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    session = _get_session(use_tor=True)

    try:
        response = session.get(url, headers=headers, timeout=40)
        if response.status_code != 200:
            return []

        soup = BeautifulSoup(response.text, "html.parser")
        links = []
        for a in soup.find_all("a"):
            try:
                href = a.get("href", "")
                title = a.get_text(strip=True)
                onion_links = re.findall(r"https?://[a-z0-9.]+\.onion[^\s]*", href)
                if onion_links and "search" not in onion_links[0] and len(title) > 3:
                    links.append({
                        "title": title,
                        "link": onion_links[0],
                        "search_engine": engine_name,
                    })
            except Exception:
                continue
        return links

    except Exception as e:
        logger.debug("Search engine %s failed: %s", engine_name, str(e)[:100])
        return []


def search_dark_web(
    queries: list[dict[str, str]],
    max_workers: int = 5,
) -> list[dict[str, str]]:
    """Execute multiple queries across all search engines.

    Args:
        queries: list of {"query": str, "category": str}
        max_workers: thread pool size

    Returns:
        Deduplicated list of {"title", "link", "search_engine", "category"}
    """
    all_results: list[dict[str, str]] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for q in queries:
            query_text = q["query"]
            category = q["category"]
            for engine in SEARCH_ENGINES:
                future = executor.submit(
                    _search_single_engine,
                    engine["url"],
                    engine["name"],
                    query_text,
                )
                futures.append((future, category))

        for future, category in futures:
            try:
                results = future.result(timeout=PAGE_TIMEOUT)
                for r in results:
                    r["category"] = category
                all_results.extend(results)
            except Exception as e:
                logger.debug("Search future failed: %s", str(e)[:100])

    # Deduplicate by link
    seen: set[str] = set()
    unique: list[dict[str, str]] = []
    for r in all_results:
        link = r.get("link", "").rstrip("/")
        if link and link not in seen:
            seen.add(link)
            unique.append(r)

    logger.info("Dark web search: %d unique results from %d total", len(unique), len(all_results))
    return unique


# ── Scraping ──

def _scrape_single(url_data: dict[str, str]) -> dict[str, Any]:
    """Scrape a single .onion URL and return structured result."""
    url = (url_data.get("link") or "").strip()
    title = (url_data.get("title") or "Untitled").strip()
    engine = url_data.get("search_engine", "")
    category = url_data.get("category", "")

    if not url:
        return {"url": "", "title": title, "text": "", "engine": engine, "category": category}

    parsed = urlparse(url)
    use_tor = (parsed.hostname or "").lower().endswith(".onion")

    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8",
    }

    response = None
    scraped_text = ""
    http_status = 0
    content_length = 0

    try:
        session = _get_session(use_tor=use_tor)
        timeout = (10, PAGE_TIMEOUT) if use_tor else (5, 25)
        response = session.get(url, headers=headers, timeout=timeout, stream=True)
        http_status = response.status_code

        if response.status_code == 200:
            content_type = (response.headers.get("Content-Type") or "").lower()
            if content_type and not any(t in content_type for t in ALLOWED_CONTENT_TYPES):
                return {
                    "url": url, "title": title, "text": "",
                    "engine": engine, "category": category,
                    "http_status": http_status, "content_length": 0,
                }

            chunks = []
            bytes_read = 0
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                bytes_read += len(chunk)
                if bytes_read > MAX_DOWNLOAD_BYTES:
                    break
                chunks.append(chunk)

            content_length = bytes_read
            html = b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup(["script", "style"]):
                tag.extract()
            text = soup.get_text(separator=" ")
            text = " ".join(text.split())
            scraped_text = text[:MAX_EXTRACTED_TEXT_CHARS]

    except Exception as e:
        logger.debug("Scrape failed for %s: %s", url[:60], str(e)[:100])
    finally:
        if response is not None:
            response.close()

    # Truncate for return
    if len(scraped_text) > MAX_RETURN_CHARS:
        scraped_text = scraped_text[:MAX_RETURN_CHARS - 15] + "...(truncated)"

    return {
        "url": url,
        "title": title,
        "text": f"{title} - {scraped_text}" if scraped_text else title,
        "engine": engine,
        "category": category,
        "http_status": http_status,
        "content_length": content_length,
        "scraped_at": datetime.utcnow().isoformat(),
    }


def scrape_results(
    search_results: list[dict[str, str]],
    max_workers: int = 5,
    progress_cb: Optional[Callable[[int, int], None]] = None,
) -> list[dict[str, Any]]:
    """Scrape multiple .onion URLs concurrently.

    Args:
        search_results: output from search_dark_web()
        max_workers: thread pool size
        progress_cb: optional (done, total) callback for SSE updates

    Returns:
        List of scrape result dicts with text content.
    """
    # Deduplicate by URL
    seen: set[str] = set()
    unique: list[dict[str, str]] = []
    for item in search_results:
        url = (item.get("link") or "").strip()
        if url and url not in seen:
            seen.add(url)
            unique.append(item)

    total = len(unique)
    results: list[dict[str, Any]] = []
    done = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {
            executor.submit(_scrape_single, item): item
            for item in unique
        }
        for future in as_completed(future_to_url):
            try:
                result = future.result(timeout=PAGE_TIMEOUT)
                if result.get("text"):
                    results.append(result)
            except Exception as e:
                logger.debug("Scrape worker failed: %s", str(e)[:100])

            done += 1
            if progress_cb:
                progress_cb(done, total)

    logger.info("Scraping complete: %d/%d pages returned content", len(results), total)
    return results
