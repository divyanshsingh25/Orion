import html
from reportlab.platypus import Paragraph, Spacer, PageBreak, KeepTogether, Table, TableStyle
from reportlab.graphics.shapes import Drawing, Polygon, Group, String, Rect
from reportlab.lib.units import inch

from app.reports.styles import get_styles, Colors
from app.reports.components import (
    create_metric_grid, create_severity_badge, create_evidence_box, create_remediation_card, 
    create_data_table, create_horizontal_bar_chart, create_risk_gauge
)

STYLES = get_styles()

class ReportBuilder:
    def __init__(self, payload):
        self.payload = payload
        self.story = []

    def _safe_str(self, val):
        if val is None: return "N/A"
        s = str(val)
        s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        s = s.replace('"', "&quot;").replace("'", "&apos;")
        return s

    def _get_severity_rank(self, severity):
        s = str(severity).upper()
        if s == "CRITICAL": return 5
        if s == "HIGH": return 4
        if s == "MEDIUM": return 3
        if s == "LOW": return 2
        return 1

    def build_section_header(self, number, title):
        self.story.append(Spacer(1, 15))
        self.story.append(Paragraph(f"<font color='{Colors.CYAN_ACCENT.hexval()}'>{number}</font>", STYLES["FindingHeaderID"]))
        self.story.append(Paragraph(title, STYLES["OrionH1"]))

    def build_cover(self):
        # We rely on generator.py's onFirstPage to draw the full cover image
        self.story.append(PageBreak())

    def build_target_details(self):
        target = self._safe_str(self.payload.get('scan_info', {}).get('target', 'N/A'))
        date_str = self._safe_str(self.payload.get('generated_at', 'N/A'))
        try:
            date_str = date_str.split("T")[0] + " " + date_str.split("T")[1][:5] + " UTC"
        except Exception:
            pass
            
        self.story.append(Spacer(1, 100))
        
        # Target Info Panel
        info_data = [
            [
                Paragraph("TARGET", STYLES["CoverLabel"]),
                Paragraph("ASSESSMENT TYPE", STYLES["CoverLabel"])
            ],
            [
                Paragraph(target, STYLES["CoverValue"]),
                Paragraph("Full Scan", STYLES["CoverValue"])
            ],
            [
                Paragraph("ASSESSMENT DATE", STYLES["CoverLabel"]),
                Paragraph("REPORT VERSION", STYLES["CoverLabel"])
            ],
            [
                Paragraph(date_str, STYLES["CoverValue"]),
                Paragraph("1.0", STYLES["CoverValue"])
            ],
            [
                Paragraph("CLASSIFICATION", STYLES["CoverLabel"]),
                ""
            ],
            [
                Paragraph("CONFIDENTIAL", STYLES["CoverValue"]),
                ""
            ]
        ]
        
        info_table = Table(info_data, colWidths=[234, 234])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), Colors.DARK_NAVY),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('LEFTPADDING', (0,0), (-1,-1), 20),
            ('RIGHTPADDING', (0,0), (-1,-1), 20),
            ('TOPPADDING', (0,0), (-1,-1), 10),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('BOX', (0,0), (-1,-1), 1, Colors.SLATE_800)
        ]))
        
        self.story.append(info_table)
        self.story.append(PageBreak())

    def build_executive_summary(self):
        self.build_section_header("01", "EXECUTIVE SUMMARY")
        
        scan_info = self.payload.get('scan_info', {})
        findings = self.payload.get("findings", [])
        num_findings = len(findings)
        endpoints = scan_info.get("endpoints_discovered", 0)
        requests = scan_info.get("requests_made", 0)
        duration = scan_info.get('duration_seconds', 0)
        cvss = self.payload.get('cvss_analysis', {})
        dist = self.payload.get('severity_distribution', {})
        risk_score = self.payload.get('overall_risk_score', 0)
        
        # Executive Statement
        exec_stmt = f"ORION identified {num_findings} security finding{'s' if num_findings != 1 else ''} during the assessment, covering {endpoints} endpoint{'s' if endpoints != 1 else ''} and {requests} request{'s' if requests != 1 else ''}."
        self.story.append(Paragraph(exec_stmt, STYLES["OrionBody"]))
        self.story.append(Spacer(1, 30))
        
        # Two-column visual: Risk Score & Severity
        risk_drawing = create_risk_gauge(risk_score)
        dist_drawing = create_horizontal_bar_chart(dist)
        
        two_col_data = [
            [Paragraph("<b>SECURITY RISK SCORE</b>", STYLES["FindingSectionLabel"]), Paragraph("<b>FINDING SEVERITY</b>", STYLES["FindingSectionLabel"])],
            [risk_drawing, dist_drawing]
        ]
        
        two_col = Table(two_col_data, colWidths=[234, 234])
        two_col.setStyle(TableStyle([
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ]))
        self.story.append(two_col)
        self.story.append(Spacer(1, 30))
        
        # Metrics Row
        metrics = [
            ("Findings", str(num_findings)),
            ("Endpoints", str(endpoints)),
            ("Requests", str(requests)),
            ("Duration", f"{duration:.1f}s")
        ]
        self.story.append(create_metric_grid(metrics))
        self.story.append(Spacer(1, 30))
        
        # Executive Insight
        self.story.append(Paragraph("<b>EXECUTIVE INSIGHT</b>", STYLES["FindingSectionLabel"]))
        
        crit_high = cvss.get("critical", 0) + cvss.get("high", 0)
        if crit_high == 0:
            if num_findings == 0:
                insight = "No security findings were identified during this assessment."
            else:
                insight = f"No critical or high-severity findings were identified in this assessment. The assessment identified {cvss.get('medium', 0)} medium-severity finding(s), {cvss.get('low', 0)} low-severity finding(s), and {cvss.get('info', 0)} informational finding(s)."
        else:
            insight = f"The assessment identified {crit_high} critical/high severity findings that require immediate remediation. In total, {num_findings} findings were discovered."
            
        self.story.append(Paragraph(insight, STYLES["OrionBody"]))
        self.story.append(PageBreak())

    def build_assessment_overview(self):
        self.build_section_header("02", "ASSESSMENT OVERVIEW")
        
        scan_info = self.payload.get('scan_info', {})
        headers = ["Property", "Value"]
        rows = [
            ["Target URL", scan_info.get("target")],
            ["Assessment Type", scan_info.get("scan_type")],
            ["Start Time", scan_info.get("started_at")],
            ["Completion Time", scan_info.get("completed_at")],
            ["Duration (seconds)", f"{scan_info.get('duration_seconds', 0):.2f}"],
            ["Requests Made", str(scan_info.get("requests_made", 0))],
            ["Endpoints Discovered", str(scan_info.get("endpoints_discovered", 0))],
        ]
        self.story.append(create_data_table(headers, rows, [200, 268]))
        self.story.append(PageBreak())

    def build_methodology(self):
        self.build_section_header("03", "SCOPE & METHODOLOGY")
        
        self.story.append(Paragraph("This assessment was performed using the Orion Automated Web Application Security Assessment Engine. The testing methodology integrates passive reconnaissance, automated attack surface discovery, transport layer analysis, and active vulnerability verification probes. All checks adhere to safe, non-destructive testing standards and are strictly confined to authorized target scope.", STYLES["OrionBody"]))
        self.story.append(Spacer(1, 10))
        
        self.story.append(Paragraph("Security Checks Performed", STYLES["OrionH2"]))
        self.story.append(Spacer(1, 6))

        from reportlab.lib.styles import ParagraphStyle
        
        cat_header_style = ParagraphStyle(
            'MethodologyCat',
            parent=STYLES['OrionBody'],
            fontName='Helvetica-Bold',
            fontSize=8.5,
            leading=11.5,
            textColor=Colors.NAVY,
            spaceBefore=5,
            spaceAfter=2,
        )
        
        item_style = ParagraphStyle(
            'MethodologyItem',
            parent=STYLES['OrionBody'],
            fontName='Helvetica',
            fontSize=7.5,
            leading=10,
            textColor=Colors.SLATE_700,
            spaceBefore=1,
            spaceAfter=1,
        )
        
        col1_elements = [
            Paragraph("<font color='#2563eb'><b>RECONNAISSANCE & ASSET DISCOVERY</b></font>", cat_header_style),
            Paragraph("&bull; <b>DNS Record Enumeration:</b> A, AAAA, MX, NS, TXT, SOA records", item_style),
            Paragraph("&bull; <b>Subdomain Discovery:</b> Dictionary resolution of 45 common prefixes", item_style),
            Paragraph("&bull; <b>WHOIS Intelligence:</b> Domain registration, registrar & nameservers", item_style),
            Paragraph("&bull; <b>Web Scope Crawling:</b> Page traversal, robots.txt, sitemap.xml", item_style),
            Paragraph("&bull; <b>Technology Detection:</b> Server banners, CMS, and framework stacks", item_style),
            Paragraph("&bull; <b>SPA Discovery:</b> Client-side JS rendering & XHR/fetch route capture", item_style),
            Spacer(1, 5),
            Paragraph("<font color='#2563eb'><b>TRANSPORT & NETWORK SECURITY</b></font>", cat_header_style),
            Paragraph("&bull; <b>TLS Protocol Support:</b> TLS 1.2+ enforcement & deprecated protocol checks", item_style),
            Paragraph("&bull; <b>Cipher Suite Analysis:</b> Insecure cipher suites & &lt;128-bit key length", item_style),
            Paragraph("&bull; <b>X.509 Certificate Validation:</b> Expiration, self-signed & trust chain checks", item_style),
            Spacer(1, 5),
            Paragraph("<font color='#2563eb'><b>API SECURITY & QUALITY GATES</b></font>", cat_header_style),
            Paragraph("&bull; <b>REST Method Enumeration:</b> TRACE method & state-changing HTTP access", item_style),
            Paragraph("&bull; <b>Excessive Data Exposure:</b> PII detection & unpaginated response limits", item_style),
            Paragraph("&bull; <b>GraphQL Security:</b> Introspection query, depth limits & batch abuse", item_style),
            Paragraph("&bull; <b>Evidence Replay Verification:</b> Live replay of High/Critical detections", item_style),
            Paragraph("&bull; <b>Quality Pipeline:</b> SHA256 root-cause correlation & CVSS v3.1 scoring", item_style),
        ]
        
        col2_elements = [
            Paragraph("<font color='#2563eb'><b>SECURITY POSTURE & CONFIGURATION</b></font>", cat_header_style),
            Paragraph("&bull; <b>Content-Security-Policy:</b> Missing CSP & unsafe-inline/eval directives", item_style),
            Paragraph("&bull; <b>HSTS Enforcement:</b> Strict-Transport-Security presence & max-age", item_style),
            Paragraph("&bull; <b>Anti-Clickjacking:</b> X-Frame-Options & CSP frame-ancestors controls", item_style),
            Paragraph("&bull; <b>MIME-Sniffing Defense:</b> X-Content-Type-Options nosniff verification", item_style),
            Paragraph("&bull; <b>CORS Policy:</b> Arbitrary origin reflection, credentials & wildcards", item_style),
            Paragraph("&bull; <b>Cookie Flags:</b> Secure, HttpOnly, and SameSite attribute enforcement", item_style),
            Paragraph("&bull; <b>JWT Token Security:</b> Algorithm 'none', expiration & weak HMAC secrets", item_style),
            Spacer(1, 5),
            Paragraph("<font color='#2563eb'><b>APPLICATION VULNERABILITY TESTING</b></font>", cat_header_style),
            Paragraph("&bull; <b>Cross-Site Scripting (XSS):</b> Parameter injection & context reflection", item_style),
            Paragraph("&bull; <b>SQL Injection:</b> Error-based, boolean, time-based blind & UNION flaws", item_style),
            Paragraph("&bull; <b>SSRF:</b> Cloud metadata (AWS/GCP) & loopback differential testing", item_style),
            Paragraph("&bull; <b>File Inclusion & Traversal:</b> LFI/path traversal for sensitive files", item_style),
            Paragraph("&bull; <b>XML External Entity (XXE):</b> External DTD entity resolution probes", item_style),
            Paragraph("&bull; <b>Command / Code Injection (RCE):</b> Shell delimiters & execution checks", item_style),
            Paragraph("&bull; <b>Access Control (IDOR):</b> Identifier mutation & sensitive data leakage", item_style),
            Paragraph("&bull; <b>Open Redirect:</b> Unvalidated 3xx location and meta redirection checks", item_style),
            Paragraph("&bull; <b>NoSQL & LDAP Injection:</b> Operator injection & LDAP filter characters", item_style),
            Paragraph("&bull; <b>Template Injection (SSTI):</b> Arithmetic evaluation across 7 engines", item_style),
            Paragraph("&bull; <b>CSRF Protection:</b> State-changing form token presence verification", item_style),
        ]
        
        table_data = [[col1_elements, col2_elements]]
        methodology_table = Table(table_data, colWidths=[230, 238])
        methodology_table.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('LEFTPADDING', (0,0), (-1,-1), 0),
            ('RIGHTPADDING', (0,0), (0,-1), 10),
            ('RIGHTPADDING', (1,0), (1,-1), 0),
            ('TOPPADDING', (0,0), (-1,-1), 0),
            ('BOTTOMPADDING', (0,0), (-1,-1), 0),
        ]))
        
        self.story.append(methodology_table)
        self.story.append(PageBreak())

    def build_target_recon(self):
        self.build_section_header("04", "TARGET INFORMATION")
        
        # IPs
        self.story.append(Paragraph("IP Addresses", STYLES["OrionH2"]))
        ips = self.payload.get("ip_addresses", [])
        if ips:
            self.story.append(Paragraph(", ".join([str(i) for i in ips]), STYLES["OrionCodeBlack"]))
        else:
            self.story.append(Paragraph("No IP addresses resolved.", STYLES["OrionBody"]))
            
        # Subdomains
        self.story.append(Paragraph("Discovered Subdomains", STYLES["OrionH2"]))
        subs = self.payload.get("dns_information", {}).get("subdomains", [])
        if subs:
            subs = sorted(list(set(subs)))
            self.story.append(Paragraph(", ".join([str(s) for s in subs]), STYLES["OrionCodeBlack"]))
        else:
            self.story.append(Paragraph("No subdomains discovered.", STYLES["OrionBody"]))
            
        # Ports
        self.story.append(Paragraph("Open Ports & Services", STYLES["OrionH2"]))
        ports = self.payload.get("open_ports", [])
        if ports:
            p_rows = []
            for p in ports:
                p_rows.append([str(p.get("port", "")), str(p.get("protocol", "")).upper(), str(p.get("state", "")).title(), str(p.get("service", ""))])
            self.story.append(create_data_table(["Port", "Protocol", "State", "Service"], p_rows, [80, 80, 80, 228]))
        else:
            self.story.append(Paragraph("No open ports discovered.", STYLES["OrionBody"]))
            
        # TLS
        tls = self.payload.get("tls", {})
        if tls and isinstance(tls, dict):
            self.story.append(Paragraph("TLS Configuration", STYLES["OrionH2"]))
            t_rows = []
            for k, v in tls.items():
                t_rows.append([str(k).replace("_", " ").title(), str(v)[:200]])
            if t_rows:
                self.story.append(create_data_table(["Property", "Value"], t_rows, [120, 348]))

        self.story.append(PageBreak())

    def build_findings_summary_table(self):
        self.build_section_header("05", "FINDINGS OVERVIEW")
        findings = self.payload.get("findings", [])
        
        if not findings:
            self.story.append(Paragraph("NO SECURITY FINDINGS IDENTIFIED", STYLES["OrionBody"]))
            self.story.append(PageBreak())
            return
            
        # Deduplicate to finding types
        grouped = self._group_findings(findings)
        sorted_groups = sorted(
            grouped.items(),
            key=lambda item: (
                self._get_severity_rank(item[1][0].get("severity", "")),
                float(item[1][0].get("cvss_score") or 0)
            ),
            reverse=True
        )
        
        headers = ["ID", "Title", "Severity", "CVSS", "CWE", "Confidence"]
        rows = []
        for i, (title, items) in enumerate(sorted_groups):
            f = items[0]
            f_id = f"VUL-{i+1:03d}"
            
            cwe_display = str(f.get("cwe_id", "N/A"))
            # Safely omit CWE if none
            if not cwe_display or cwe_display.lower() == "none" or cwe_display == "N/A":
                cwe_display = "N/A"
                
            rows.append([
                f_id,
                Paragraph(self._safe_str(title), STYLES['OrionBody']),
                create_severity_badge(f.get("severity", "Info")),
                str(f.get("cvss_score", "N/A")),
                cwe_display,
                str(f.get("confidence", "CONFIRMED")).upper()
            ])
            
        self.story.append(create_data_table(headers, rows, [60, 168, 80, 40, 60, 60]))
        self.story.append(PageBreak())
        
        # Detailed sections map to these same IDs
        self.sorted_groups = sorted_groups

    def _group_findings(self, findings):
        grouped = {}
        for finding in findings:
            base_title = finding.get("title", "Untitled Finding")
            import re
            base_title = re.sub(r'"[^"]+"', '"..."', base_title)
            base_title = re.sub(r"'[^']+'", "'...'", base_title)
            if base_title not in grouped:
                grouped[base_title] = []
            grouped[base_title].append(finding)
        return grouped

    def build_detailed_findings(self):
        self.build_section_header("06", "DETAILED FINDINGS")
        findings = self.payload.get("findings", [])
        if not findings:
            self.story.append(Paragraph("NO SECURITY FINDINGS IDENTIFIED", STYLES["OrionBody"]))
            return

        if not hasattr(self, 'sorted_groups'):
            self.sorted_groups = sorted(
                self._group_findings(findings).items(),
                key=lambda item: (self._get_severity_rank(item[1][0].get("severity", "")), float(item[1][0].get("cvss_score") or 0)),
                reverse=True
            )

        for i, (title, items) in enumerate(self.sorted_groups):
            f = items[0]
            f_id = f"VUL-{i+1:03d}"
            
            # Header + Classification
            header_elements = []
            header_elements.append(Paragraph(f_id, STYLES["FindingHeaderID"]))
            header_elements.append(Paragraph(self._safe_str(title).upper(), STYLES["FindingHeaderTitle"]))
            
            meta_rows = [
                ["Severity:", create_severity_badge(f.get("severity", "Info")), "CVSS v3.1:", str(f.get("cvss_score", "N/A"))],
                ["Confidence:", str(f.get("confidence", "CONFIRMED")).upper(), "", ""]
            ]
            header_elements.append(create_data_table(None, meta_rows, [80, 100, 80, 208]))
            header_elements.append(Spacer(1, 10))
            
            cwe_str = f"{f.get('cwe_id', 'N/A')} - {f.get('cwe_name', '')}" if f.get('cwe_id') else "N/A"
            if cwe_str.startswith("N/A -"): cwe_str = "N/A"
                
            class_rows = [
                ["OWASP:", self._safe_str(f.get("owasp_category", "N/A"))],
                ["CWE:", cwe_str],
                ["CVSS Vector:", self._safe_str(f.get("cvss_vector", "N/A"))]
            ]
            header_elements.append(Paragraph("CLASSIFICATION", STYLES["FindingSectionLabel"]))
            header_elements.append(create_data_table(None, class_rows, [100, 368]))
            header_elements.append(Spacer(1, 10))
            self.story.append(KeepTogether(header_elements))

            # Description
            desc_elements = []
            desc_elements.append(Paragraph("DESCRIPTION", STYLES["FindingSectionLabel"]))
            desc_elements.append(Paragraph(self._safe_str(f.get("description", "N/A")).replace("\n", "<br/>"), STYLES["OrionBody"]))
            desc_elements.append(Spacer(1, 10))
            self.story.append(KeepTogether(desc_elements))
            
            # Affected Endpoints & Evidence
            if len(items) > 1:
                ep_elements = []
                ep_elements.append(Paragraph("AFFECTED COMPONENT & EVIDENCE", STYLES["FindingSectionLabel"]))
                ep_elements.append(Paragraph(f"Affected Endpoints: {len(items)}", STYLES["OrionBody"]))
                # Grouped table
                ep_rows = []
                for item in items:
                    ep_rows.append([
                        Paragraph(self._safe_str(item.get("affected_url")), STYLES["OrionCodeBlack"]),
                        Paragraph(self._safe_str(item.get("affected_parameter")), STYLES["OrionCodeBlack"])
                    ])
                ep_elements.append(create_data_table(["Endpoint", "Parameter"], ep_rows, [300, 168]))
                ep_elements.append(Spacer(1, 10))
                self.story.append(KeepTogether(ep_elements))
                
                # Show one evidence block as sample
                if f.get("evidence"):
                    ev_elements = []
                    ev_elements.append(Paragraph("Evidence Sample:", STYLES["OrionBody"]))
                    ev_elements.append(create_evidence_box(f.get("evidence")))
                    ev_elements.append(Spacer(1, 10))
                    self.story.append(KeepTogether(ev_elements))
            else:
                comp_elements = []
                comp_elements.append(Paragraph("AFFECTED COMPONENT & EVIDENCE", STYLES["FindingSectionLabel"]))
                comp_rows = [
                    ["Endpoint:", Paragraph(self._safe_str(f.get("affected_url", "N/A")), STYLES["OrionCodeBlack"])],
                    ["Parameter:", Paragraph(self._safe_str(f.get("affected_parameter", "N/A")), STYLES["OrionCodeBlack"])]
                ]
                comp_elements.append(create_data_table(["Component", "Details"], comp_rows, [100, 368]))
                comp_elements.append(Spacer(1, 10))
                self.story.append(KeepTogether(comp_elements))
                
                if f.get("evidence"):
                    ev_elements = []
                    ev_elements.append(create_evidence_box(f.get("evidence")))
                    ev_elements.append(Spacer(1, 10))
                    self.story.append(KeepTogether(ev_elements))
                    
            if f.get("verification_guidance"):
                ver_elements = []
                ver_elements.append(Paragraph("RETEST GUIDANCE", STYLES["FindingSectionLabel"]))
                ver_elements.append(Paragraph(self._safe_str(f.get("verification_guidance")).replace("\n", "<br/>"), STYLES["OrionBody"]))
                ver_elements.append(Spacer(1, 10))
                self.story.append(KeepTogether(ver_elements))

            # Remediation
            rem_elements = []
            rem_elements.append(create_remediation_card(f.get("remediation", "N/A")))
            rem_elements.append(Spacer(1, 30))
            self.story.append(KeepTogether(rem_elements))

    def build_remediation_roadmap(self):
        self.build_section_header("07", "REMEDIATION PRIORITY")
        
        if not hasattr(self, 'sorted_groups'):
            return
            
        headers = ["ID", "Finding", "Severity", "Priority"]
        rows = []
        for i, (title, items) in enumerate(self.sorted_groups):
            f_id = f"VUL-{i+1:03d}"
            f = items[0]
            sev = f.get("severity", "").lower()
            
            priority = "Hardening"
            if sev == "critical": priority = "Immediate Action"
            elif sev == "high": priority = "High Priority"
            elif sev == "medium": priority = "Planned Remediation"
            
            rows.append([
                f_id,
                Paragraph(self._safe_str(title), STYLES['OrionBody']),
                create_severity_badge(f.get("severity", "Info")),
                priority
            ])
            
        self.story.append(create_data_table(headers, rows, [60, 208, 80, 120]))

    def build(self):
        self.build_cover()
        self.build_target_details()
        self.build_executive_summary()
        self.build_assessment_overview()
        self.build_methodology()
        self.build_target_recon()
        self.build_findings_summary_table()
        self.build_detailed_findings()
        self.build_remediation_roadmap()
        return self.story
