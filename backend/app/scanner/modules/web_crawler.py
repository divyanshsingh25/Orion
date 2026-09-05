"""Real web crawler module.

Discovers pages, links, forms, parameters, API endpoints, JS files,
robots.txt, and sitemap.xml — staying within the authorized target scope.
"""

from __future__ import annotations

import asyncio
from html.parser import HTMLParser
from typing import Any, Callable, Awaitable
from urllib.parse import urljoin, urlparse
import re

import aiohttp


EmitFn = Callable[[dict[str, Any]], Awaitable[None] | None]


class _PageParser(HTMLParser):
    """Parse an HTML page for links, forms, scripts, and inputs."""

    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.scripts: list[str] = []
        self.inputs: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(urljoin(self.base_url, a["href"]))
        elif tag == "form":
            self._current_form = {
                "action": urljoin(self.base_url, a.get("action", "")),
                "method": a.get("method", "GET").upper(),
                "inputs": [],
            }
            self.forms.append(self._current_form)
        elif tag in {"input", "textarea", "select"}:
            field = {
                "type": a.get("type", tag),
                "name": a.get("name", ""),
                "value": a.get("value", ""),
            }
            self.inputs.append({**field, "url": self.base_url})
            if self._current_form is not None:
                self._current_form["inputs"].append(field)
        elif tag == "script" and a.get("src"):
            self.scripts.append(urljoin(self.base_url, a["src"]))
        elif tag == "link" and a.get("href"):
            self.links.append(urljoin(self.base_url, a["href"]))

    def handle_endtag(self, tag: str):
        if tag == "form":
            self._current_form = None


async def run_web_crawler(
    session: aiohttp.ClientSession,
    target_url: str,
    *,
    max_pages: int = 50,
    emit: EmitFn | None = None,
) -> dict[str, Any]:
    """Crawl *target_url* and discover pages, forms, params, endpoints.

    Returns::

        {
            "pages": [{"url": ..., "status": ..., "content_type": ...}],
            "forms": [...],
            "inputs": [...],
            "scripts": [...],
            "links": [...],
            "api_endpoints": [...],
            "robots_txt": str | None,
            "sitemap_xml": str | None,
            "requests_made": int,
            "endpoints_discovered": int,
        }
    """

    parsed_target = urlparse(target_url)
    target_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"

    visited: set[str] = set()
    to_visit: list[str] = [target_url]

    all_pages: list[dict[str, Any]] = []
    all_forms: list[dict[str, Any]] = []
    all_inputs: list[dict[str, Any]] = []
    all_scripts: list[str] = []
    all_links: list[str] = []
    api_endpoints: list[str] = []
    requests_made = 0

    # --- robots.txt ---
    robots_txt = await _fetch_text(session, urljoin(target_url, "/robots.txt"))
    requests_made += 1
    if robots_txt and emit:
        await _safe_emit(emit, "[CRAWLER] Found robots.txt")
        # Extract paths from robots.txt
        for line in robots_txt.splitlines():
            line = line.strip()
            if line.lower().startswith(("disallow:", "allow:")):
                path = line.split(":", 1)[1].strip()
                if path and path != "/" and "*" not in path:
                    full_url = urljoin(target_url, path)
                    if full_url not in visited and full_url not in to_visit:
                        to_visit.append(full_url)

    # --- sitemap.xml ---
    sitemap_xml = await _fetch_text(session, urljoin(target_url, "/sitemap.xml"))
    requests_made += 1
    if sitemap_xml and emit:
        await _safe_emit(emit, "[CRAWLER] Found sitemap.xml")
        # Extract URLs from sitemap
        urls_in_sitemap = re.findall(r"<loc>(.*?)</loc>", sitemap_xml, re.I)
        for u in urls_in_sitemap[:20]:
            if u.startswith(target_origin) and u not in visited and u not in to_visit:
                to_visit.append(u)

    # --- Crawl pages ---
    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        normalized = _normalize_url(url)

        if normalized in visited:
            continue
        # Stay within scope
        if not url.startswith(target_origin):
            continue

        visited.add(normalized)

        if emit:
            path = urlparse(url).path or "/"
            await _safe_emit(emit, f"[CRAWLER] GET {path}")

        try:
            async with session.get(url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                requests_made += 1
                status = resp.status
                content_type = resp.headers.get("Content-Type", "")

                page_info: dict[str, Any] = {
                    "url": str(resp.url),
                    "status": status,
                    "content_type": content_type,
                }
                all_pages.append(page_info)

                if emit:
                    await _safe_emit(emit, f"[CRAWLER] {status} {urlparse(str(resp.url)).path}")

                # Only parse HTML responses
                if "text/html" not in content_type:
                    # Check if it looks like an API endpoint
                    if "json" in content_type or "xml" in content_type:
                        api_endpoints.append(str(resp.url))
                        if emit:
                            await _safe_emit(emit, f"[CRAWLER] API endpoint discovered: {urlparse(str(resp.url)).path}")
                    continue

                html = await resp.text(errors="ignore")

        except Exception:
            continue

        # Parse the page
        parser = _PageParser(str(resp.url))
        try:
            parser.feed(html)
        except Exception:
            continue

        all_forms.extend(parser.forms)
        all_inputs.extend(parser.inputs)
        all_scripts.extend(parser.scripts)

        # Process discovered links
        for link in parser.links:
            link_parsed = urlparse(link)
            # Stay within scope
            if not link.startswith(target_origin):
                continue
            link_normalized = _normalize_url(link)
            if link_normalized not in visited and link not in to_visit:
                # Check for API patterns
                path = link_parsed.path.lower()
                if any(seg in path for seg in ("/api/", "/rest/", "/v1/", "/v2/", "/graphql")):
                    api_endpoints.append(link)
                to_visit.append(link)
                all_links.append(link)

        # Check for query parameters and extract as url_param inputs for vulnerability scanners
        for link in parser.links:
            lp = urlparse(link)
            if lp.query and link.startswith(target_origin):
                all_links.append(link)
                from urllib.parse import parse_qs
                for p_name, p_vals in parse_qs(lp.query).items():
                    all_inputs.append({
                        "type": "url_param",
                        "name": p_name,
                        "value": p_vals[0] if p_vals else "",
                        "url": link,
                    })

    # If few inputs were discovered, generate candidate test parameters on crawled pages
    candidate_param_names = ["id", "page", "q", "search", "url", "file", "redirect", "category", "lang", "email", "view", "ref"]
    existing_param_keys = {(inp.get("url"), inp.get("name")) for inp in all_inputs if inp.get("type") == "url_param"}
    for page_info in all_pages[:15]:
        page_url = page_info.get("url", "")
        if not page_url:
            continue
        for cp in candidate_param_names[:6]:
            if (page_url, cp) not in existing_param_keys:
                all_inputs.append({
                    "type": "url_param",
                    "name": cp,
                    "value": "1",
                    "url": page_url,
                })
                existing_param_keys.add((page_url, cp))

    # Deduplicate
    all_scripts = list(dict.fromkeys(all_scripts))
    all_links = list(dict.fromkeys(all_links))
    api_endpoints = list(dict.fromkeys(api_endpoints))

    endpoints_discovered = len(all_pages) + len(api_endpoints)

    if emit:
        await _safe_emit(
            emit,
            f"[CRAWLER] Complete - {len(all_pages)} pages, {len(all_forms)} forms, "
            f"{len(api_endpoints)} API endpoints, {requests_made} requests",
        )

    return {
        "pages": all_pages,
        "forms": all_forms,
        "inputs": all_inputs,
        "scripts": all_scripts,
        "links": all_links[:200],
        "api_endpoints": api_endpoints,
        "robots_txt": robots_txt,
        "sitemap_xml": sitemap_xml,
        "requests_made": requests_made,
        "endpoints_discovered": endpoints_discovered,
    }


def _normalize_url(url: str) -> str:
    """Normalize URL for dedup: strip fragment, trailing slash."""
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") or "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}{'?' + parsed.query if parsed.query else ''}"


async def _fetch_text(session: aiohttp.ClientSession, url: str) -> str | None:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            if resp.status < 400:
                return await resp.text(errors="ignore")
    except Exception:
        pass
    return None


async def _safe_emit(emit: EmitFn, message: str) -> None:
    import asyncio as _aio
    result = emit({"log_message": message})
    if _aio.iscoroutine(result):
        await result
