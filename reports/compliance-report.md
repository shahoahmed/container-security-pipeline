# Container Compliance Report

**Image:** `compliance-demo-app:demo-run`  
**Generated:** 2026-06-21T18:49:07.918913+00:00  
**Standard:** NIST SP 800-171 / DFARS 252.204-7012

## Summary

| Severity | Count |
|---|---|
| CRITICAL | 2 |
| HIGH | 3 |
| MEDIUM | 3 |
| LOW | 1 |

**Total findings:** 9  
**Fixable (patch available):** 8  
**Weighted risk score:** 42

## NIST 800-171 Control Coverage

Controls touched by at least one finding in this scan, ordered by how many findings map to each:

| Control | Findings mapped |
|---|---|
| 3.11.2 - Periodically scan for vulnerabilities | 9 |
| 3.14.1 - Identify, report, and correct system flaws in a timely manner | 9 |
| 3.11.3 - Remediate vulnerabilities in accordance with risk assessments | 5 |
| 3.13.1 - Monitor, control, and protect organizational communications | 5 |
| 3.13.8 - Implement cryptographic mechanisms to protect CUI in transit | 2 |
| 3.4.2 - Establish and enforce security configuration settings | 2 |
| 3.5.1 - Identify and authenticate organizational users | 2 |
| 3.1.5 - Employ the principle of least privilege | 1 |

## Findings Detail

| CVE | Package | Severity | Installed | Fixed In | Mapped Controls |
|---|---|---|---|---|---|
| DEMO-CVE-2024-1001 | openssl | CRITICAL | 1.1.1n-0+deb11u4 | 1.1.1n-0+deb11u5 | 3.11.2<br>3.11.3<br>3.13.1<br>3.13.8<br>3.14.1<br>3.4.2 |
| DEMO-CVE-2024-1002 | libc-bin | CRITICAL | 2.31-13+deb11u5 | 2.31-13+deb11u7 | 3.1.5<br>3.11.2<br>3.11.3<br>3.13.1<br>3.14.1<br>3.4.2 |
| DEMO-CVE-2023-2045 | zlib1g | HIGH | 1.2.11.dfsg-2+deb11u2 | 1.2.11.dfsg-2+deb11u3 | 3.11.2<br>3.11.3<br>3.13.1<br>3.14.1 |
| DEMO-CVE-2023-2099 | curl | HIGH | 7.74.0-1.3+deb11u7 | 7.74.0-1.3+deb11u9 | 3.11.2<br>3.11.3<br>3.13.8<br>3.14.1<br>3.5.1 |
| DEMO-CVE-2023-5050 | Flask | HIGH | 2.0.1 | 2.3.2 | 3.11.2<br>3.11.3<br>3.14.1<br>3.5.1 |
| DEMO-CVE-2022-3311 | ncurses-base | MEDIUM | 6.2+20201114-2 | not available | 3.11.2<br>3.14.1 |
| DEMO-CVE-2022-3312 | tar | MEDIUM | 1.34+dfsg-1 | 1.34+dfsg-1+deb11u1 | 3.11.2<br>3.13.1<br>3.14.1 |
| DEMO-CVE-2023-5099 | Werkzeug | MEDIUM | 2.0.1 | 2.3.3 | 3.11.2<br>3.13.1<br>3.14.1 |
| DEMO-CVE-2021-4002 | gzip | LOW | 1.10-4 | 1.10-4+deb11u1 | 3.11.2<br>3.14.1 |
