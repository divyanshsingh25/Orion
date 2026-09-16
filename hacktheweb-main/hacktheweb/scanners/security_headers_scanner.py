"""
Security Headers Scanner
Checks for missing or misconfigured HTTP security headers on target responses.
"""

from typing import List, Dict, Any
from urllib.parse import urlparse


class SecurityHeadersScanner:
    """Scanner for security headers vulnerabilities with accurate standards checking."""
    
    def __init__(self, config, session):
        """Initialize security headers scanner."""
        self.config = config
        self.session = session
        
    async def scan(self, target: str, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan target for missing or misconfigured security headers."""
        vulnerabilities = []
        
        try:
            status_code = recon_data.get('status_code', 200)
            raw_headers = recon_data.get('headers')
            
            if not raw_headers or not isinstance(raw_headers, dict):
                async with self.session.get(target, timeout=8) as response:
                    raw_headers = dict(response.headers)
                    status_code = response.status
            
            # Case-insensitive header dictionary
            headers_lower = {k.lower(): v for k, v in raw_headers.items()}
            observed_header_names = ", ".join(sorted(raw_headers.keys()))
            is_https = target.lower().startswith('https://')
            
            csp_val = headers_lower.get('content-security-policy', '')
            has_csp_frame_ancestors = 'frame-ancestors' in csp_val.lower()

            # 1. Content-Security-Policy (CSP)
            if 'content-security-policy' not in headers_lower:
                vulnerabilities.append({
                    'type': 'security_headers',
                    'severity': 'low',
                    'confidence': 'Confirmed',
                    'verification_status': 'confirmed',
                    'cvss': 3.7,
                    'url': target,
                    'affected_url': target,
                    'header_name': 'Content-Security-Policy',
                    'affected_parameter': 'Content-Security-Policy',
                    'title': 'Missing Content-Security-Policy header',
                    'description': 'The Content-Security-Policy (CSP) header is not set. CSP helps prevent Cross-Site Scripting (XSS), clickjacking, and data injection attacks.',
                    'evidence': (
                        f"Endpoint: {target}\n"
                        f"Status: HTTP {status_code}\n"
                        f"Missing Header: Content-Security-Policy\n"
                        f"Observed Headers: {observed_header_names}\n"
                        f"Detection Reason: Header absent in HTTP response"
                    ),
                    'remediation': "Define and deploy a strict Content-Security-Policy (e.g., Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none').",
                    'cwe': 'CWE-693',
                    'owasp': 'A05:2021 - Security Misconfiguration',
                })
            else:
                csp_issues = []
                if "'unsafe-inline'" in csp_val.lower():
                    csp_issues.append("uses 'unsafe-inline'")
                if "'unsafe-eval'" in csp_val.lower():
                    csp_issues.append("uses 'unsafe-eval'")
                if csp_issues:
                    vulnerabilities.append({
                        'type': 'security_headers',
                        'severity': 'low',
                        'confidence': 'Confirmed',
                        'verification_status': 'confirmed',
                        'cvss': 3.1,
                        'url': target,
                        'affected_url': target,
                        'header_name': 'Content-Security-Policy',
                        'affected_parameter': 'Content-Security-Policy',
                        'title': 'Weak Content-Security-Policy directives',
                        'description': f'Content-Security-Policy contains potentially weak directives: {", ".join(csp_issues)}.',
                        'evidence': (
                            f"Endpoint: {target}\n"
                            f"Status: HTTP {status_code}\n"
                            f"Header Value: Content-Security-Policy: {csp_val}\n"
                            f"Detection Reason: CSP contains unsafe keywords: {', '.join(csp_issues)}"
                        ),
                        'remediation': "Avoid 'unsafe-inline' and 'unsafe-eval'. Use nonces or hashes for inline scripts.",
                        'cwe': 'CWE-693',
                        'owasp': 'A05:2021 - Security Misconfiguration',
                    })

            # 2. HTTP Strict Transport Security (HSTS) — Only applicable to HTTPS
            if is_https:
                hsts_val = headers_lower.get('strict-transport-security', '')
                if not hsts_val:
                    vulnerabilities.append({
                        'type': 'security_headers',
                        'severity': 'low',
                        'confidence': 'Confirmed',
                        'verification_status': 'confirmed',
                        'cvss': 3.7,
                        'url': target,
                        'affected_url': target,
                        'header_name': 'Strict-Transport-Security',
                        'affected_parameter': 'Strict-Transport-Security',
                        'title': 'Missing HTTP Strict Transport Security (HSTS) header',
                        'description': 'The target is served over HTTPS but lacks the Strict-Transport-Security header, allowing potential downgrade or SSL-stripping attacks.',
                        'evidence': (
                            f"Endpoint: {target}\n"
                            f"Status: HTTP {status_code}\n"
                            f"Missing Header: Strict-Transport-Security\n"
                            f"Observed Headers: {observed_header_names}\n"
                            f"Detection Reason: HSTS header missing on HTTPS target"
                        ),
                        'remediation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
                        'cwe': 'CWE-319',
                        'owasp': 'A05:2021 - Security Misconfiguration',
                    })
                elif 'max-age=' not in hsts_val.lower():
                    vulnerabilities.append({
                        'type': 'security_headers',
                        'severity': 'low',
                        'confidence': 'Confirmed',
                        'verification_status': 'confirmed',
                        'cvss': 2.7,
                        'url': target,
                        'affected_url': target,
                        'header_name': 'Strict-Transport-Security',
                        'affected_parameter': 'Strict-Transport-Security',
                        'title': 'Misconfigured HSTS max-age directive',
                        'description': 'Strict-Transport-Security header is present but missing a valid max-age directive.',
                        'evidence': (
                            f"Endpoint: {target}\n"
                            f"Status: HTTP {status_code}\n"
                            f"Header Value: Strict-Transport-Security: {hsts_val}\n"
                            f"Detection Reason: Missing max-age directive in HSTS"
                        ),
                        'remediation': 'Configure max-age with at least 31536000 seconds (1 year).',
                        'cwe': 'CWE-319',
                        'owasp': 'A05:2021 - Security Misconfiguration',
                    })

            # 3. X-Content-Type-Options
            xcto_val = headers_lower.get('x-content-type-options', '').strip()
            if not xcto_val:
                vulnerabilities.append({
                    'type': 'security_headers',
                    'severity': 'low',
                    'confidence': 'Confirmed',
                    'verification_status': 'confirmed',
                    'cvss': 3.1,
                    'url': target,
                    'affected_url': target,
                    'header_name': 'X-Content-Type-Options',
                    'affected_parameter': 'X-Content-Type-Options',
                    'title': 'Missing X-Content-Type-Options header',
                    'description': 'The X-Content-Type-Options: nosniff header is missing, allowing browsers to MIME-sniff response payloads.',
                    'evidence': (
                        f"Endpoint: {target}\n"
                        f"Status: HTTP {status_code}\n"
                        f"Missing Header: X-Content-Type-Options\n"
                        f"Observed Headers: {observed_header_names}\n"
                        f"Detection Reason: Header absent in HTTP response"
                    ),
                    'remediation': 'Add: X-Content-Type-Options: nosniff',
                    'cwe': 'CWE-693',
                    'owasp': 'A05:2021 - Security Misconfiguration',
                })
            elif 'nosniff' not in xcto_val.lower():
                vulnerabilities.append({
                    'type': 'security_headers',
                    'severity': 'low',
                    'confidence': 'Confirmed',
                    'verification_status': 'confirmed',
                    'cvss': 2.5,
                    'url': target,
                    'affected_url': target,
                    'header_name': 'X-Content-Type-Options',
                    'affected_parameter': 'X-Content-Type-Options',
                    'title': 'Misconfigured X-Content-Type-Options header',
                    'description': f'X-Content-Type-Options is set to "{xcto_val}" instead of "nosniff".',
                    'evidence': (
                        f"Endpoint: {target}\n"
                        f"Status: HTTP {status_code}\n"
                        f"Header Value: X-Content-Type-Options: {xcto_val}\n"
                        f"Detection Reason: Value does not specify nosniff"
                    ),
                    'remediation': 'Set: X-Content-Type-Options: nosniff',
                    'cwe': 'CWE-693',
                    'owasp': 'A05:2021 - Security Misconfiguration',
                })

            # 4. X-Frame-Options (only required if CSP frame-ancestors is absent)
            if not has_csp_frame_ancestors:
                xfo_val = headers_lower.get('x-frame-options', '').strip().lower()
                if not xfo_val:
                    vulnerabilities.append({
                        'type': 'security_headers',
                        'severity': 'low',
                        'confidence': 'Confirmed',
                        'verification_status': 'confirmed',
                        'cvss': 3.7,
                        'url': target,
                        'affected_url': target,
                        'header_name': 'X-Frame-Options',
                        'affected_parameter': 'X-Frame-Options',
                        'title': 'Missing anti-clickjacking header (X-Frame-Options / frame-ancestors)',
                        'description': 'Neither X-Frame-Options nor CSP frame-ancestors is set, making the page potentially embeddable in cross-origin iframes.',
                        'evidence': (
                            f"Endpoint: {target}\n"
                            f"Status: HTTP {status_code}\n"
                            f"Missing Headers: X-Frame-Options, Content-Security-Policy (frame-ancestors)\n"
                            f"Observed Headers: {observed_header_names}\n"
                            f"Detection Reason: Page lacks clickjacking protection headers"
                        ),
                        'remediation': 'Add: X-Frame-Options: DENY (or SAMEORIGIN), or use CSP frame-ancestors.',
                        'cwe': 'CWE-1021',
                        'owasp': 'A05:2021 - Security Misconfiguration',
                    })
                elif xfo_val not in ('deny', 'sameorigin'):
                    vulnerabilities.append({
                        'type': 'security_headers',
                        'severity': 'low',
                        'confidence': 'Confirmed',
                        'verification_status': 'confirmed',
                        'cvss': 2.7,
                        'url': target,
                        'affected_url': target,
                        'header_name': 'X-Frame-Options',
                        'affected_parameter': 'X-Frame-Options',
                        'title': 'Weak X-Frame-Options configuration',
                        'description': f'X-Frame-Options is set to "{xfo_val}". Recommended values are DENY or SAMEORIGIN.',
                        'evidence': (
                            f"Endpoint: {target}\n"
                            f"Status: HTTP {status_code}\n"
                            f"Header Value: X-Frame-Options: {xfo_val}\n"
                            f"Detection Reason: Non-standard or weak X-Frame-Options value"
                        ),
                        'remediation': 'Set X-Frame-Options to DENY or SAMEORIGIN.',
                        'cwe': 'CWE-1021',
                        'owasp': 'A05:2021 - Security Misconfiguration',
                    })

            # 5. Referrer-Policy
            if 'referrer-policy' not in headers_lower:
                vulnerabilities.append({
                    'type': 'security_headers',
                    'severity': 'low',
                    'confidence': 'Confirmed',
                    'verification_status': 'confirmed',
                    'cvss': 2.5,
                    'url': target,
                    'affected_url': target,
                    'header_name': 'Referrer-Policy',
                    'affected_parameter': 'Referrer-Policy',
                    'title': 'Missing Referrer-Policy header',
                    'description': 'The Referrer-Policy header is absent. Setting this header protects sensitive URL query parameters from leaking to external referrers.',
                    'evidence': (
                        f"Endpoint: {target}\n"
                        f"Status: HTTP {status_code}\n"
                        f"Missing Header: Referrer-Policy\n"
                        f"Observed Headers: {observed_header_names}\n"
                        f"Detection Reason: Header absent in HTTP response"
                    ),
                    'remediation': 'Add: Referrer-Policy: strict-origin-when-cross-origin',
                    'cwe': 'CWE-200',
                    'owasp': 'A05:2021 - Security Misconfiguration',
                })

            # 6. Information Disclosure Headers (Server banners, technology versions)
            for info_hdr, desc in [
                ('x-powered-by', 'X-Powered-By reveals server backend framework'),
                ('x-aspnet-version', 'X-AspNet-Version reveals ASP.NET framework version'),
                ('x-aspnetmvc-version', 'X-AspNetMvc-Version reveals ASP.NET MVC version'),
            ]:
                if info_hdr in headers_lower:
                    hdr_val = headers_lower[info_hdr]
                    vulnerabilities.append({
                        'type': 'information_disclosure',
                        'severity': 'low',
                        'confidence': 'Confirmed',
                        'verification_status': 'confirmed',
                        'cvss': 2.0,
                        'url': target,
                        'affected_url': target,
                        'header_name': info_hdr,
                        'affected_parameter': info_hdr,
                        'title': f'Technology disclosure in {info_hdr} header',
                        'description': f'{desc}: {hdr_val}',
                        'evidence': (
                            f"Endpoint: {target}\n"
                            f"Status: HTTP {status_code}\n"
                            f"Header: {info_hdr}: {hdr_val}\n"
                            f"Detection Reason: Framework identifier disclosed in HTTP response"
                        ),
                        'remediation': f'Remove or suppress the {info_hdr} header in web server configuration.',
                        'cwe': 'CWE-200',
                        'owasp': 'A05:2021 - Security Misconfiguration',
                    })

        except Exception as e:
            pass
        
        return vulnerabilities
