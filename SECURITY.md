# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes    |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report security issues privately to: **dragon.day33@gmail.com**

Include in your report:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You can expect an acknowledgement within **48 hours** and a resolution timeline within **7 days** for confirmed issues.

## Scope

Security reports are welcome for:
- Vulnerabilities in reconmap itself (code execution, path traversal, injection, SSRF, etc.)
- Issues in the Docker image or CI/CD configuration
- API endpoint security issues
- Dependency vulnerabilities with direct exploitability

## Responsible Use

reconmap performs **fully passive** reconnaissance only — it queries public data sources and does not actively probe targets. Even so, use it only against domains you own or have **explicit written authorization** to monitor. The maintainers are not responsible for unauthorized use of this software.
