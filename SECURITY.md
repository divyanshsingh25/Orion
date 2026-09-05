# Security Policy & Authorized Testing Guidelines

## Authorized Use

ORION is an automated security assessment platform designed and intended exclusively for:
- Authorized penetration testing and security assessments.
- Defensive security evaluations, audits, and internal vulnerability management.
- Academic, educational, and security research purposes conducted within isolated, controlled, or explicitly authorized environments.

Users must ensure they have explicit, documented, and verifiable permission from the rightful owner or authorized administrator of any system, network, application, or domain before conducting scans or tests using ORION.

---

## Prohibited Use

Any use of ORION against targets without prior explicit authorization is strictly prohibited. Specifically, users must NOT:
- Target, scan, probe, or test any network, server, computer system, web application, or API without explicit written consent from the owner.
- Perform tests that disrupt system availability, degrade performance, or result in denial-of-service (DoS) conditions for production systems or shared resources.
- Attempt unauthorized data exfiltration, data destruction, system compromise, or lateral movement outside approved testing parameters.
- Violate any local, national, or international computer fraud, cybersecurity, or data privacy laws (such as the United States Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, or equivalent regional legislation).

**The author, maintainers, and contributors do not authorize, endorse, or encourage unauthorized, malicious, or unlawful use of this software.**

---

## Scope and Authorization

Before initiating any security assessment:
- **Define Explicit Rules of Engagement (RoE)**: Clearly establish testing schedules, in-scope targets, allowable test methods, and emergency communication channels with stakeholders.
- **Verify Target Boundaries**: Ensure that all target URLs, hostnames, IP addresses, and endpoints belong strictly within the agreed assessment scope.
- **Third-Party Infrastructure**: Be aware that modern applications often rely on cloud service providers, Content Delivery Networks (CDNs), shared hosting, and third-party APIs. Users must ensure that scanning activities comply with third-party acceptable use policies and cloud provider penetration testing policies.
- **Sole User Responsibility**: Users are solely responsible for obtaining and verifying all required permissions before running scans.

---

## Responsible Testing Practices

When utilizing ORION:
- **Safe Testing Methods**: Prioritize non-destructive vulnerability identification and proof-of-concept verification. Avoid payloads that could cause persistent modifications, data corruption, or system instability.
- **Rate Limiting and Concurrency**: Configure request delays and concurrency limits appropriate for the target environment to prevent resource exhaustion.
- **Immediate Cessation**: If a scan causes unanticipated service degradation, error spikes, or adverse effects on a target, halt testing immediately and notify target administrators.
- **Data Protection**: Handle all discovered vulnerability data, logs, session tokens, and security findings confidentially and securely.

---

## Reporting Security Issues in ORION

If you discover a security vulnerability within the ORION platform itself (such as in the backend API, frontend dashboard, or authentication workflows), we welcome responsible disclosure:

1. **Do NOT open a public issue** disclosing the vulnerability details.
2. Submit your findings privately via **GitHub Private Vulnerability Reporting** on the repository, or contact the maintainers directly through private channels.
3. Include detailed reproduction steps, environment details, and proof-of-concept information to assist in validating and remediating the issue.

We strive to review, acknowledge, and address valid security reports in a timely manner.

---

## Disclaimer

ORION is provided "AS IS", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement.

**No Guarantee of Legal Immunity:**
Neither this policy, the project documentation, nor the software itself guarantees legal immunity or eliminates legal liability. Users are solely responsible for compliance with all applicable laws, regulations, contracts, and terms of service. Under no circumstances shall the author, contributors, or copyright holders be liable for any claim, damages, regulatory penalties, or other liability arising from the use, misuse, or inability to use this software.
