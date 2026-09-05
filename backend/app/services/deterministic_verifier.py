from __future__ import annotations

import re
from typing import Any, Dict, Tuple


class DeterministicVerifier:
    """Deterministic, rule-based ground-truth verification for scanner findings."""

    @classmethod
    def verify(cls, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Perform deterministic verification on raw finding evidence.

        Returns:
            {
                "verdict": "CONFIRMED" | "POTENTIAL" | "FALSE_POSITIVE",
                "confidence": float (0.0 to 1.0),
                "reasoning": str,
                "checks_applied": list[str],
            }
        """
        finding_type = str(finding.get("finding_type", finding.get("type", ""))).lower()
        evidence = str(finding.get("evidence") or "")
        http_req = str(finding.get("http_request") or "")
        http_res = str(finding.get("http_response") or "")
        title = str(finding.get("title") or "").lower()
        description = str(finding.get("description") or "").lower()

        combined_text = f"{evidence} {http_res} {description}"

        # 1. XSS Verification Rules
        if any(k in finding_type or k in title for k in ["xss", "cross-site scripting", "script injection"]):
            return cls._verify_xss(finding, evidence, http_req, http_res, combined_text)

        # 2. HTTP Method & OPTIONS Rules
        if any(k in finding_type or k in title for k in ["http_method", "insecure_method", "options", "verb_tampering", "allow_header"]):
            return cls._verify_http_methods(finding, evidence, http_req, http_res)

        # 3. CVE & Version Banner Rules
        if any(k in finding_type or k in title for k in ["cve", "version", "outdated", "banner", "known_vulnerability"]):
            return cls._verify_cve_banner(finding, evidence, http_req, http_res)

        # 4. SQL Injection Rules
        if any(k in finding_type or k in title for k in ["sqli", "sql injection", "database injection"]):
            return cls._verify_sqli(finding, evidence, http_res)

        # 5. Default Fallback
        return {
            "verdict": "POTENTIAL",
            "confidence": 0.50,
            "reasoning": "Standard scanner finding without deterministic rule override; requires contextual AI evidence evaluation.",
            "checks_applied": ["default_fallback"],
        }

    @classmethod
    def _verify_xss(
        cls,
        finding: Dict[str, Any],
        evidence: str,
        http_req: str,
        http_res: str,
        combined_text: str,
    ) -> Dict[str, Any]:
        checks = []

        # Check 1: Non-executable content-types (e.g. application/json, text/plain)
        ct_match = re.search(r"(?i)content-type\s*:\s*([^\r\n;]+)", http_res)
        if ct_match:
            content_type = ct_match.group(1).strip().lower()
            checks.append(f"content_type_check: {content_type}")
            if any(safe_ct in content_type for safe_ct in ["application/json", "text/plain", "application/octet-stream"]):
                return {
                    "verdict": "FALSE_POSITIVE",
                    "confidence": 0.92,
                    "reasoning": f"Payload reflected inside non-executable Content-Type ({content_type}). Browser will not parse HTML/JavaScript.",
                    "checks_applied": checks,
                }

        # Check 2: HTML Entity Encoding
        if any(encoded in http_res for encoded in ["&lt;script&gt;", "&lt;img", "&quot;", "&#39;", "&#x3c;"]):
            checks.append("entity_encoding_detected")
            # If payload tags are escaped, it is not executable
            if "<script" not in http_res and "<img" not in http_res and "<svg" not in http_res:
                return {
                    "verdict": "FALSE_POSITIVE",
                    "confidence": 0.90,
                    "reasoning": "Special HTML characters (<, >, \", ') were safely entity-encoded by the server before reflection.",
                    "checks_applied": checks,
                }

        # Check 3: Reflection alone without proof of executable DOM context
        payload_tag = re.search(r"(<script[^>]*>|<img[^>]+onerror|<svg[^>]+onload)", http_res, re.I)
        if payload_tag:
            checks.append("raw_unencoded_tag_reflected")
            # Check for Strict CSP blocking inline scripts
            if re.search(r"(?i)content-security-policy\s*:.*script-src\s+'none'", http_res):
                return {
                    "verdict": "POTENTIAL",
                    "confidence": 0.65,
                    "reasoning": "Raw payload reflected in HTML, but Content-Security-Policy (CSP) restricts script execution.",
                    "checks_applied": checks + ["csp_restriction_found"],
                }
            return {
                "verdict": "CONFIRMED",
                "confidence": 0.88,
                "reasoning": f"Unencoded executable HTML/JS payload ({payload_tag.group(0)}) reflected in HTML response body without entity escaping.",
                "checks_applied": checks,
            }

        # Reflection was noted by scanner, but evidence does not show unencoded tag execution
        return {
            "verdict": "POTENTIAL",
            "confidence": 0.55,
            "reasoning": "Reflection observed in scan evidence, but executable HTML/DOM context requires deeper verification.",
            "checks_applied": checks + ["reflection_alone_guard"],
        }

    @classmethod
    def _verify_http_methods(
        cls,
        finding: Dict[str, Any],
        evidence: str,
        http_req: str,
        http_res: str,
    ) -> Dict[str, Any]:
        checks = ["http_methods_check"]

        # If evidence is only an Allow: header or OPTIONS response
        has_allow_header = bool(re.search(r"(?i)allow\s*:\s*.*(?:PUT|DELETE|TRACE)", http_res or evidence))
        has_options_req = bool(re.search(r"(?i)OPTIONS\s+/", http_req or evidence))

        # Check if actual PUT/DELETE action was tested
        has_put_execution = bool(re.search(r"(?i)(?:PUT|DELETE)\s+\S+\s+HTTP", http_req or evidence))
        put_success = bool(re.search(r"(?i)HTTP/\d\.\d\s+(?:200|201|204)\s+", http_res or evidence))
        put_rejected = bool(re.search(r"(?i)HTTP/\d\.\d\s+(?:401|403|405|501)\s+", http_res or evidence))

        if has_put_execution and put_success:
            return {
                "verdict": "CONFIRMED",
                "confidence": 0.90,
                "reasoning": "Actual HTTP PUT/DELETE request returned 2xx Success, confirming unauthorized method execution.",
                "checks_applied": checks + ["active_method_execution_verified"],
            }

        if has_put_execution and put_rejected:
            return {
                "verdict": "FALSE_POSITIVE",
                "confidence": 0.92,
                "reasoning": "Server rejected actual HTTP PUT/DELETE request with 4xx/5xx status, confirming effective access controls.",
                "checks_applied": checks + ["active_method_rejected"],
            }

        if has_allow_header or has_options_req:
            return {
                "verdict": "POTENTIAL",
                "confidence": 0.50,
                "reasoning": "OPTIONS Allow header indicates supported verbs, but actual method behavior and state alteration are unverified.",
                "checks_applied": checks + ["allow_header_insufficient_evidence_guard"],
            }

        return {
            "verdict": "POTENTIAL",
            "confidence": 0.45,
            "reasoning": "HTTP method finding lacks sufficient request/response evidence to confirm exploitability.",
            "checks_applied": checks,
        }

    @classmethod
    def _verify_cve_banner(
        cls,
        finding: Dict[str, Any],
        evidence: str,
        http_req: str,
        http_res: str,
    ) -> Dict[str, Any]:
        checks = ["cve_banner_check"]

        has_active_exploit = bool(
            re.search(r"(?i)(?:root:x:0:0|uid=\d+|windows\\win\.ini|bin/sh|eval-stdin)", evidence + http_res)
        )
        if has_active_exploit:
            return {
                "verdict": "CONFIRMED",
                "confidence": 0.95,
                "reasoning": "Active exploit proof (e.g. system file or command output) captured in evidence.",
                "checks_applied": checks + ["active_exploit_proof_found"],
            }

        # Passive banner matching alone
        is_banner_match = bool(
            re.search(r"(?i)(?:server|x-powered-by|version|banner)\s*:\s*[a-zA-Z0-9_\-\.\/]+", evidence + http_res)
        )
        if is_banner_match or "version" in finding.get("title", "").lower():
            return {
                "verdict": "POTENTIAL",
                "confidence": 0.50,
                "reasoning": "Finding is based on passive version/banner identification. Backported security patches or deceptive banners may apply.",
                "checks_applied": checks + ["passive_banner_match_guard"],
            }

        return {
            "verdict": "POTENTIAL",
            "confidence": 0.50,
            "reasoning": "CVE finding requires active exploitation or deeper telemetry to confirm.",
            "checks_applied": checks,
        }

    @classmethod
    def _verify_sqli(cls, finding: Dict[str, Any], evidence: str, http_res: str) -> Dict[str, Any]:
        checks = ["sqli_check"]
        sql_errors = [
            r"syntax error in string",
            r"mysql_fetch_array",
            r"ORA-\d{5}",
            r"PostgreSQL.*ERROR",
            r"sqlite3\.OperationalError",
            r"Microsoft OLE DB Provider for SQL Server",
            r"Unclosed quotation mark after the character string",
        ]

        found_error = any(re.search(pattern, evidence + http_res, re.I) for pattern in sql_errors)
        if found_error:
            return {
                "verdict": "CONFIRMED",
                "confidence": 0.92,
                "reasoning": "Database engine syntax error signature reflected in response after injection payload.",
                "checks_applied": checks + ["database_error_reflected"],
            }

        return {
            "verdict": "POTENTIAL",
            "confidence": 0.55,
            "reasoning": "SQL injection indicator observed; differential analysis recommended.",
            "checks_applied": checks,
        }
