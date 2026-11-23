# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes    |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report security issues privately through GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/dragonday3/reconmap/security/advisories/new)** (Security tab → *Report a vulnerability*).

Only the maintainer can see the report.

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

reconmap is **passive-first**: crt.sh, Shodan InternetDB and GitHub search never touch the target, and the only direct traffic is ordinary DNS lookups (including 20 common subdomain guesses, skippable with `--no-dns`). It performs no port scanning or HTTP probing. Even so, use it only against domains you own or have **explicit written authorization** to monitor. The maintainers are not responsible for unauthorized use of this software.
