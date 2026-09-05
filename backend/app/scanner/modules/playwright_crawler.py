"""ORION Playwright Deep Crawler.

Uses Playwright (headless Chromium) to execute JavaScript, discover SPA routes,
intercept XHR/fetch/WebSocket traffic, and find GraphQL endpoints.

Falls back gracefully if Playwright is not installed.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Awaitable, Callable
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("orion.playwright")

EmitFn = Callable[[dict[str, Any]], Awaitable[None] | None]

# Check if Playwright is available
try:
    from playwright.async_api import async_playwright, Page, BrowserContext
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.info("Playwright not installed — deep crawling disabled")


def _can_run_subprocesses() -> bool:
    """Check if the active event loop supports subprocess execution."""
    import sys
    import asyncio
    try:
        loop = asyncio.get_running_loop()
        # On Windows with SelectorEventLoop, subprocesses raise NotImplementedError
        if sys.platform == "win32" and not hasattr(loop, "_proactor"):
            return False
        return True
    except Exception:
        return True


async def run_playwright_crawl(
    target_url: str,
    *,
    max_pages: int = 30,
    timeout_seconds: float = 60.0,
    auth_cookies: dict[str, str] | None = None,
    auth_headers: dict[str, str] | None = None,
    emit: EmitFn | None = None,
) -> dict[str, Any]:
    """Run a Playwright-based deep crawl of *target_url*.

    Discovers:
      - SPA routes (by clicking navigation elements)
      - XHR/fetch API calls
      - WebSocket connections
      - GraphQL endpoints
      - Forms and inputs from the rendered DOM
      - Parameters from intercepted requests

    Returns a dict similar to web_crawler output, ready to merge.
    """
    if not PLAYWRIGHT_AVAILABLE or not _can_run_subprocesses():
        if emit:
            await _safe_emit(emit, "[PLAYWRIGHT] Deep browser crawl skipped (using fast HTTP crawler fallback)")
        return _empty_result()

    parsed = urlparse(target_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    discovered_urls: set[str] = set()
    api_endpoints: list[dict[str, Any]] = []
    xhr_requests: list[dict[str, Any]] = []
    websocket_urls: list[str] = []
    graphql_endpoints: list[str] = []
    forms: list[dict[str, Any]] = []
    inputs: list[dict[str, Any]] = []
    parameters: list[dict[str, Any]] = []
    pages_visited: list[dict[str, Any]] = []
    requests_made = 0

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent="ORION Security Assessment Platform/1.0",
                ignore_https_errors=True,
                java_script_enabled=True,
            )

            # Inject auth cookies if provided
            if auth_cookies:
                cookie_list = []
                for name, value in auth_cookies.items():
                    cookie_list.append({
                        "name": name,
                        "value": value,
                        "domain": parsed.hostname or "",
                        "path": "/",
                    })
                if cookie_list:
                    await context.add_cookies(cookie_list)

            # Inject auth headers if provided
            if auth_headers:
                await context.set_extra_http_headers(auth_headers)

            page = await context.new_page()

            # --- Intercept network requests ---
            async def on_request(request):
                nonlocal requests_made
                requests_made += 1
                req_url = request.url
                method = request.method
                resource = request.resource_type

                # Only track same-origin requests
                if not req_url.startswith(origin):
                    return

                # Detect XHR/fetch
                if resource in ("xhr", "fetch"):
                    xhr_entry = {
                        "url": req_url,
                        "method": method,
                        "resource_type": resource,
                    }
                    # Capture POST body if available
                    try:
                        post_data = request.post_data
                        if post_data:
                            xhr_entry["body"] = post_data[:512]
                            # Extract parameters from POST body
                            _extract_params(req_url, post_data, parameters)
                    except Exception:
                        pass

                    xhr_requests.append(xhr_entry)

                    # Detect API patterns
                    path = urlparse(req_url).path.lower()
                    if any(seg in path for seg in ("/api/", "/rest/", "/v1/", "/v2/", "/v3/")):
                        api_endpoints.append({"url": req_url, "method": method})

                    # Detect GraphQL
                    if "graphql" in path or "gql" in path:
                        if req_url not in graphql_endpoints:
                            graphql_endpoints.append(req_url)

                # Detect WebSocket upgrades
                if resource == "websocket":
                    websocket_urls.append(req_url)

                # Track URL parameters
                parsed_req = urlparse(req_url)
                if parsed_req.query:
                    _extract_query_params(req_url, parsed_req.query, parameters)

            page.on("request", on_request)

            # --- Navigate to target ---
            if emit:
                await _safe_emit(emit, f"[PLAYWRIGHT] Navigating to {target_url}")

            try:
                await page.goto(target_url, wait_until="networkidle", timeout=timeout_seconds * 1000)
            except Exception as exc:
                # Try with domcontentloaded instead
                try:
                    await page.goto(target_url, wait_until="domcontentloaded", timeout=30000)
                except Exception:
                    if emit:
                        await _safe_emit(emit, f"[PLAYWRIGHT] Navigation failed: {exc}")
                    await browser.close()
                    return _empty_result()

            discovered_urls.add(target_url)
            pages_visited.append({"url": target_url, "status": 200})

            if emit:
                await _safe_emit(emit, "[PLAYWRIGHT] Page loaded — extracting DOM")

            # --- Extract forms and inputs from rendered DOM ---
            page_forms = await _extract_forms(page, target_url)
            forms.extend(page_forms)

            page_inputs = await _extract_inputs(page, target_url)
            inputs.extend(page_inputs)

            # --- Discover navigation links ---
            nav_links = await page.evaluate("""() => {
                const links = new Set();
                document.querySelectorAll('a[href], [role="link"], [onclick]').forEach(el => {
                    const href = el.getAttribute('href');
                    if (href && !href.startsWith('#') && !href.startsWith('javascript:') && !href.startsWith('mailto:')) {
                        try {
                            links.add(new URL(href, window.location.origin).href);
                        } catch(e) {}
                    }
                });
                // Also check router links (React Router, Vue Router, etc.)
                document.querySelectorAll('[data-to], [to], [routerlink]').forEach(el => {
                    const to = el.getAttribute('data-to') || el.getAttribute('to') || el.getAttribute('routerlink');
                    if (to) {
                        try {
                            links.add(new URL(to, window.location.origin).href);
                        } catch(e) {}
                    }
                });
                return Array.from(links);
            }""")

            for link in nav_links:
                if link.startswith(origin) and link not in discovered_urls:
                    discovered_urls.add(link)

            # --- Click navigation elements to discover SPA routes ---
            nav_selectors = [
                "nav a", "aside a", "[role='navigation'] a",
                ".nav-link", ".menu-item a", ".sidebar a",
                "button[data-to]", "[routerlink]",
            ]

            visited_spa_count = 0
            for selector in nav_selectors:
                if visited_spa_count >= max_pages:
                    break
                try:
                    elements = await page.query_selector_all(selector)
                    for el in elements[:10]:  # Limit clicks per selector
                        if visited_spa_count >= max_pages:
                            break
                        try:
                            href = await el.get_attribute("href")
                            if href and href.startswith(origin) and href in discovered_urls:
                                continue

                            await el.click(timeout=3000)
                            await page.wait_for_load_state("networkidle", timeout=5000)

                            current = page.url
                            if current.startswith(origin) and current not in discovered_urls:
                                discovered_urls.add(current)
                                pages_visited.append({"url": current, "status": 200, "spa": True})
                                visited_spa_count += 1

                                if emit:
                                    path = urlparse(current).path or "/"
                                    await _safe_emit(emit, f"[PLAYWRIGHT] SPA route: {path}")

                                # Extract forms/inputs from new page
                                new_forms = await _extract_forms(page, current)
                                forms.extend(new_forms)
                                new_inputs = await _extract_inputs(page, current)
                                inputs.extend(new_inputs)

                        except Exception:
                            continue
                except Exception:
                    continue

            if emit:
                await _safe_emit(
                    emit,
                    f"[PLAYWRIGHT] Complete - {len(discovered_urls)} URLs, "
                    f"{len(xhr_requests)} XHR/fetch, {len(graphql_endpoints)} GraphQL, "
                    f"{len(websocket_urls)} WebSocket"
                )

            await browser.close()

    except Exception as exc:
        logger.info("Playwright crawler skipped/fallback active: %s", exc)
        if emit:
            await _safe_emit(emit, f"[PLAYWRIGHT] Skipped ({exc or 'headless browser unavailable'}) - using HTTP crawler fallback")
        return _empty_result()

    # Deduplicate
    api_endpoints = _dedup_dicts(api_endpoints, "url")
    xhr_requests = _dedup_dicts(xhr_requests, "url")
    parameters = _dedup_dicts(parameters, key=lambda p: f"{p['url']}|{p['name']}")

    return {
        "pages": pages_visited,
        "discovered_urls": list(discovered_urls),
        "api_endpoints": api_endpoints,
        "xhr_requests": xhr_requests,
        "websocket_urls": websocket_urls,
        "graphql_endpoints": graphql_endpoints,
        "forms": forms,
        "inputs": inputs,
        "parameters": parameters,
        "requests_made": requests_made,
        "endpoints_discovered": len(discovered_urls) + len(api_endpoints),
    }


def _empty_result() -> dict[str, Any]:
    return {
        "pages": [],
        "discovered_urls": [],
        "api_endpoints": [],
        "xhr_requests": [],
        "websocket_urls": [],
        "graphql_endpoints": [],
        "forms": [],
        "inputs": [],
        "parameters": [],
        "requests_made": 0,
        "endpoints_discovered": 0,
    }


async def _extract_forms(page: Any, base_url: str) -> list[dict[str, Any]]:
    """Extract forms from the rendered DOM."""
    try:
        return await page.evaluate("""(baseUrl) => {
            const forms = [];
            document.querySelectorAll('form').forEach(form => {
                const inputs = [];
                form.querySelectorAll('input, textarea, select').forEach(inp => {
                    inputs.push({
                        type: inp.type || inp.tagName.toLowerCase(),
                        name: inp.name || '',
                        value: inp.value || '',
                    });
                });
                forms.push({
                    action: new URL(form.action || '', baseUrl).href,
                    method: (form.method || 'GET').toUpperCase(),
                    inputs: inputs,
                });
            });
            return forms;
        }""", base_url)
    except Exception:
        return []


async def _extract_inputs(page: Any, base_url: str) -> list[dict[str, Any]]:
    """Extract all input elements from the rendered DOM."""
    try:
        return await page.evaluate("""(baseUrl) => {
            const inputs = [];
            document.querySelectorAll('input, textarea, select').forEach(inp => {
                inputs.push({
                    type: inp.type || inp.tagName.toLowerCase(),
                    name: inp.name || '',
                    value: inp.value || '',
                    url: baseUrl,
                });
            });
            return inputs;
        }""", base_url)
    except Exception:
        return []


def _extract_params(url: str, body: str, params_list: list[dict[str, Any]]) -> None:
    """Extract parameters from a POST body."""
    try:
        import json as _json
        data = _json.loads(body)
        if isinstance(data, dict):
            for key in data:
                params_list.append({"url": url, "name": key, "source": "json_body", "method": "POST"})
    except Exception:
        # Try form-encoded
        for pair in body.split("&"):
            if "=" in pair:
                key = pair.split("=", 1)[0]
                params_list.append({"url": url, "name": key, "source": "form_body", "method": "POST"})


def _extract_query_params(url: str, query: str, params_list: list[dict[str, Any]]) -> None:
    """Extract parameters from URL query string."""
    for pair in query.split("&"):
        if "=" in pair:
            key = pair.split("=", 1)[0]
            params_list.append({"url": url, "name": key, "source": "query", "method": "GET"})


def _dedup_dicts(items: list[dict], key: Any = "url") -> list[dict]:
    """Deduplicate a list of dicts by a key or callable."""
    seen: set[str] = set()
    result: list[dict] = []
    for item in items:
        k = key(item) if callable(key) else item.get(key, "")
        if k not in seen:
            seen.add(k)
            result.append(item)
    return result


async def _safe_emit(emit: EmitFn, message: str) -> None:
    import asyncio as _aio
    result = emit({"log_message": message})
    if _aio.iscoroutine(result):
        await result
