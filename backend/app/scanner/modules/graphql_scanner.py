"""ORION GraphQL Security Scanner.

Tests discovered GraphQL endpoints for common vulnerabilities:
  - Introspection enabled
  - Query depth/complexity limits
  - Batch query abuse
  - Information disclosure via error messages
  - Field suggestions leaking schema information
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import aiohttp

logger = logging.getLogger("orion.graphql_scanner")

# Introspection query
_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind }
      }
    }
  }
}
"""

# Deeply nested query for depth limit testing
_DEEP_QUERY_TEMPLATE = """
query DepthTest {{
  __typename
  {nested}
}}
"""


def _build_deep_query(depth: int = 10) -> str:
    """Build a deeply nested query to test depth limits."""
    nested = "__typename"
    for i in range(depth):
        nested = f"__schema {{ types {{ name fields {{ name type {{ {nested} }} }} }} }}"
    return f"query DepthTest {{ {nested} }}"


# Batch query for batch abuse testing
_BATCH_QUERY = [
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
]


async def scan_graphql_endpoints(
    session: aiohttp.ClientSession,
    graphql_endpoints: list[str],
    target_url: str,
    *,
    timeout: float = 10.0,
) -> list[dict[str, Any]]:
    """Scan discovered GraphQL endpoints for security issues.

    Args:
        session: aiohttp session.
        graphql_endpoints: List of GraphQL endpoint URLs.
        target_url: Base target URL.
        timeout: Per-request timeout.

    Returns:
        List of finding dicts.
    """
    findings: list[dict[str, Any]] = []
    if not graphql_endpoints:
        return findings

    checked: set[str] = set()

    for ep in graphql_endpoints[:5]:  # Limit to 5 endpoints
        if isinstance(ep, dict):
            endpoint = ep.get("url", "")
        else:
            endpoint = str(ep).strip()
        if not endpoint or endpoint in checked:
            continue
        checked.add(endpoint)

        # 1. Introspection test
        intro_findings = await _test_introspection(session, endpoint, timeout)
        findings.extend(intro_findings)

        # 2. Query depth test
        depth_findings = await _test_query_depth(session, endpoint, timeout)
        findings.extend(depth_findings)

        # 3. Batch query test
        batch_findings = await _test_batch_queries(session, endpoint, timeout)
        findings.extend(batch_findings)

        # 4. Error disclosure test
        error_findings = await _test_error_disclosure(session, endpoint, timeout)
        findings.extend(error_findings)

        # 5. Field suggestion test
        suggestion_findings = await _test_field_suggestions(session, endpoint, timeout)
        findings.extend(suggestion_findings)

        await asyncio.sleep(0.1)

    return findings


async def _test_introspection(
    session: aiohttp.ClientSession, endpoint: str, timeout: float
) -> list[dict[str, Any]]:
    """Test if GraphQL introspection is enabled."""
    findings: list[dict[str, Any]] = []

    try:
        async with session.post(
            endpoint,
            json={"query": _INTROSPECTION_QUERY},
            headers={"Content-Type": "application/json"},
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            if resp.status >= 400:
                return findings

            body = await resp.text(errors="ignore")
            data = json.loads(body)

            if "data" in data and data["data"].get("__schema"):
                schema = data["data"]["__schema"]
                type_count = len(schema.get("types", []))
                has_mutations = schema.get("mutationType") is not None

                description = (
                    f"GraphQL introspection is enabled, exposing the full API schema "
                    f"({type_count} types"
                )
                if has_mutations:
                    description += ", mutations available"
                description += "). Attackers can enumerate all queries, mutations, and types."

                findings.append({
                    "type": "graphql_security",
                    "title": "GraphQL introspection enabled",
                    "description": description,
                    "url": endpoint,
                    "affected_url": endpoint,
                    "method": "POST",
                    "detection": f"Introspection returned {type_count} types",
                    "evidence": f"Schema: {type_count} types, mutations={'yes' if has_mutations else 'no'}",
                    "severity": "Medium",
                    "confidence": "Confirmed",
                    "cwe": "CWE-200",
                    "owasp": "A05:2021 - Security Misconfiguration",
                    "remediation": "Disable GraphQL introspection in production. Only enable it in development environments.",
                })
    except Exception:
        pass

    return findings


async def _test_query_depth(
    session: aiohttp.ClientSession, endpoint: str, timeout: float
) -> list[dict[str, Any]]:
    """Test for missing query depth/complexity limits."""
    findings: list[dict[str, Any]] = []

    deep_query = _build_deep_query(depth=8)

    try:
        async with session.post(
            endpoint,
            json={"query": deep_query},
            headers={"Content-Type": "application/json"},
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            body = await resp.text(errors="ignore")

            # If the server processes a deeply nested query without error,
            # it likely lacks depth limiting
            if resp.status < 400 and "errors" not in body.lower()[:200]:
                findings.append({
                    "type": "graphql_security",
                    "title": "GraphQL missing query depth limit",
                    "description": "GraphQL endpoint accepts deeply nested queries without restriction, enabling denial-of-service via resource exhaustion.",
                    "url": endpoint,
                    "affected_url": endpoint,
                    "method": "POST",
                    "detection": "Deeply nested query (depth 8) accepted without error",
                    "severity": "Medium",
                    "confidence": "High",
                    "cwe": "CWE-770",
                    "owasp": "A04:2021 - Insecure Design",
                    "remediation": "Implement query depth limiting (recommended max depth: 5-7) and query complexity analysis.",
                })
    except asyncio.TimeoutError:
        # Timeout on deep query could indicate resource exhaustion (actually bad)
        findings.append({
            "type": "graphql_security",
            "title": "GraphQL vulnerable to query depth DoS",
            "description": "A deeply nested GraphQL query caused a timeout, indicating the server attempts to process it without depth limits.",
            "url": endpoint,
            "affected_url": endpoint,
            "method": "POST",
            "detection": "Deeply nested query caused server timeout",
            "severity": "High",
            "confidence": "High",
            "cwe": "CWE-400",
            "owasp": "A04:2021 - Insecure Design",
            "remediation": "Implement query depth and complexity limits. Reject queries exceeding safe thresholds before execution.",
        })
    except Exception:
        pass

    return findings


async def _test_batch_queries(
    session: aiohttp.ClientSession, endpoint: str, timeout: float
) -> list[dict[str, Any]]:
    """Test for batch query abuse."""
    findings: list[dict[str, Any]] = []

    try:
        async with session.post(
            endpoint,
            json=_BATCH_QUERY,
            headers={"Content-Type": "application/json"},
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            if resp.status < 400:
                body = await resp.text(errors="ignore")
                try:
                    data = json.loads(body)
                    if isinstance(data, list) and len(data) >= len(_BATCH_QUERY):
                        findings.append({
                            "type": "graphql_security",
                            "title": "GraphQL batch queries enabled without limits",
                            "description": f"GraphQL endpoint accepts batch queries (sent {len(_BATCH_QUERY)}, received {len(data)} responses). This can be abused for brute-force attacks and DoS.",
                            "url": endpoint,
                            "affected_url": endpoint,
                            "method": "POST",
                            "detection": f"Batch of {len(_BATCH_QUERY)} queries all processed",
                            "severity": "Low",
                            "confidence": "Confirmed",
                            "cwe": "CWE-770",
                            "owasp": "A04:2021 - Insecure Design",
                            "remediation": "Limit the number of queries in a single batch request (recommended: 5 or fewer).",
                        })
                except json.JSONDecodeError:
                    pass
    except Exception:
        pass

    return findings


async def _test_error_disclosure(
    session: aiohttp.ClientSession, endpoint: str, timeout: float
) -> list[dict[str, Any]]:
    """Test for information disclosure via error messages."""
    findings: list[dict[str, Any]] = []

    # Send an intentionally malformed query
    bad_queries = [
        {"query": "{ __INVALID_FIELD_12345 }"},
        {"query": "mutation { __INVALID_MUTATION_12345 }"},
        {"query": "{ "},  # Syntax error
    ]

    for bad in bad_queries:
        try:
            async with session.post(
                endpoint,
                json=bad,
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as resp:
                body = await resp.text(errors="ignore")

                # Check for stack traces, file paths, internal details
                disclosure_indicators = [
                    "stack trace", "traceback", "at line",
                    "/usr/", "/home/", "/var/", "\\node_modules\\",
                    "internal server error",
                    "sequelize", "prisma", "typeorm", "mongoose",
                    "connection string", "database",
                ]

                for indicator in disclosure_indicators:
                    if indicator in body.lower():
                        findings.append({
                            "type": "graphql_security",
                            "title": "GraphQL error messages disclose internal details",
                            "description": f"GraphQL error responses contain internal implementation details ('{indicator}'), which can aid attackers in understanding the backend.",
                            "url": endpoint,
                            "affected_url": endpoint,
                            "method": "POST",
                            "detection": f"Error response contains '{indicator}'",
                            "evidence": body[:500],
                            "severity": "Low",
                            "confidence": "Confirmed",
                            "cwe": "CWE-209",
                            "owasp": "A05:2021 - Security Misconfiguration",
                            "remediation": "Sanitize GraphQL error messages in production. Do not expose stack traces, file paths, or database details.",
                        })
                        return findings  # One finding is enough
        except Exception:
            continue

    return findings


async def _test_field_suggestions(
    session: aiohttp.ClientSession, endpoint: str, timeout: float
) -> list[dict[str, Any]]:
    """Test if GraphQL provides field suggestions (schema leakage)."""
    findings: list[dict[str, Any]] = []

    try:
        async with session.post(
            endpoint,
            json={"query": "{ user { passwor } }"},
            headers={"Content-Type": "application/json"},
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            body = await resp.text(errors="ignore")

            if "did you mean" in body.lower() or "suggestion" in body.lower():
                findings.append({
                    "type": "graphql_security",
                    "title": "GraphQL field suggestions leak schema information",
                    "description": "GraphQL endpoint provides field name suggestions in error messages, allowing attackers to enumerate the schema without introspection.",
                    "url": endpoint,
                    "affected_url": endpoint,
                    "method": "POST",
                    "detection": "Field suggestions present in error response",
                    "evidence": body[:300],
                    "severity": "Low",
                    "confidence": "Confirmed",
                    "cwe": "CWE-200",
                    "owasp": "A05:2021 - Security Misconfiguration",
                    "remediation": "Disable field suggestions in production GraphQL configuration.",
                })
    except Exception:
        pass

    return findings
