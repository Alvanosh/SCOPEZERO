# Capability boundaries — 10.8.0

This document distinguishes automated behavior from analyst-led workflows and investigation signals.

## Automated or tool-assisted workflows

- Asset discovery and service/web probing through available adapters.
- Technology observations and external vulnerability-intelligence correlation where configured sources are available.
- Bounded GET/HEAD request workflows and selected low-impact web checks.
- Authenticated identity verification and same-resource response comparison using explicitly supplied test identities.
- Persistence of scan observations, evidence metadata, notes and assessment history.

Availability depends on installed external tools, network access, provider configuration and the target environment.

## Analyst-led or heuristic workflows

- API authorization matrix entries are analyst observations; they are not automatically established authorization failures.
- Response differences between identities are leads for BOLA/IDOR investigation, not proof of a vulnerability.
- Technology-to-CVE matches require verification of exact product, version, configuration and vendor applicability.
- Reflected markers and SQL error messages are signals that require manual validation.
- Attack-path relationships and risk scores are prioritization aids, not proof of exploitability.
- Duplicate finding candidates require analyst review.

## Deliberate limitations

The release does not claim automated exploitation, SQL data extraction, blind/time-based SQL injection, executable XSS testing, active SSRF callback validation or fully automated IDOR proof. Negative results do not prove absence of vulnerabilities. HTTP GET requests can still trigger application-side effects; only test systems where those requests are authorized and safe.
