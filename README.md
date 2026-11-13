# SCOPEZERO

**Version:** 10.8.0  
**Project:** Security assessment and investigation workspace  
**Status:** Early-stage development / feedback release

SCOPEZERO is a local operator workspace for organizing authorized security assessments. It brings asset discovery, technology and vulnerability intelligence, web investigation, API access-control observations, authenticated test identities, differential checks, evidence and reporting workflows into one interface.

> **Authorization required.** Use SCOPEZERO only against systems for which you have explicit permission and a clearly defined scope. You are responsible for obtaining authorization, respecting engagement rules, and complying with applicable law.

## Current capabilities

- Engagement and scan workspace with asset and finding inventories.
- Reconnaissance and network/web discovery workflows using configured local tools.
- Technology observations and CVE/EPSS/KEV intelligence correlation.
- Web request investigation and bounded, low-impact security checks.
- API access-control observation matrix for analyst-recorded test results.
- Authenticated web test identities with encrypted request headers at rest.
- Differential response comparisons between explicitly authorized test identities.
- Evidence records, investigation notes, finding triage and reporting workflows.

Some modules are analyst-led or provide investigation signals rather than confirmed vulnerability results. CVE matches, response differences, reflected markers and error messages must be manually validated. A negative check does not prove that a vulnerability is absent. Refer to [Capability boundaries](docs/capability-boundaries.md).

## Repository layout

```text
SCOPEZERO/
├── backend/
│   ├── app/
│   │   ├── engines/
│   │   │   └── process.py
│   │   ├── main.py
│   │   ├── database.py
│   │   ├── config.py
│   │   ├── pipeline.py
│   │   └── worker.py
│   └── requirements.txt
├── frontend/
│   └── index.html
├── docs/
│   ├── architecture.md
│   ├── capability-boundaries.md
│   ├── installation-kali.md
│   └── security-and-data-handling.md
├── tests/
│   └── test_tool_execution.py
├── screenshots/
├── .env.example
├── .gitignore
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
└── README.md
```

Local databases, evidence attachments, reports, virtual environments, credentials and encryption keys are intentionally excluded from source control.

## Quick start — Kali Linux

```bash
git clone <YOUR-GITHUB-REPOSITORY-URL>
cd SCOPEZERO/backend

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000** in your browser. Keep the service bound to `127.0.0.1` for local use. See [Kali installation](docs/installation-kali.md) for details.

## Tool execution reliability — 10.8.0

This release improves local tool execution and diagnostics:

- Shared subprocess runner with process-group cleanup on timeout and captured partial stdout/stderr.
- Structured states for timeouts, launch failures, permission errors, network failures and empty successful results.
- Nmap and Nuclei preflight target caps; DNS eligibility checks are bounded and parallelized.
- Naabu uses TCP connect mode to avoid requiring raw-packet privileges for the default workflow.
- httpx uses bounded concurrency and request rate; large target sets are capped with omitted counts.
- Per-tool diagnostics include resolved binary path, elapsed time, exit code and output tails.

A cap is reported explicitly; it is not a claim that omitted hosts were scanned. Tool results remain signals requiring analyst validation.

## External tools

Some reconnaissance and assessment workflows depend on separately installed command-line tools and optional intelligence providers. The application may still start when optional tools are absent, but workflows requiring them will not be fully available. Configure only tools and providers you are authorized to use. Do not commit API keys.

## Important security notes

- Keep SCOPEZERO bound to localhost. This release is not a hardened multi-user or internet-facing deployment.
- Do not upload real engagement databases, evidence, request/response captures, reports, credentials or client data to this repository.
- The authenticated-session feature encrypts stored request headers using a local Fernet key generated at runtime. **Back up `backend/.session_vault.key` securely with the corresponding local database. Never commit or share the key.** Losing it makes stored identity headers undecryptable.
- Do not expose the app to an untrusted network. Authentication, TLS, deployment hardening and a production secrets-management design are required before any shared deployment.
- See [Security and data handling](docs/security-and-data-handling.md).

## Development and feedback

This is an early-stage project. Please report reproducible bugs, setup issues, false positives, confusing workflows and feature requests through GitHub Issues. Read [CONTRIBUTING.md](CONTRIBUTING.md) first.

## License

No open-source license has been selected for this release. Unless a license is added by the project owner, all rights are reserved; do not assume permission to redistribute or use this code commercially.


### Nuclei template selection (10.10.0)

The Nuclei adapter selects HTTP, misconfiguration, vulnerability, exposure and TLS-tagged templates, while excluding known intrusive template classes. It runs in bounded batches of five hosts (up to 25 eligible hosts per invocation), records per-batch diagnostics, and distinguishes partial completion from a successful no-match result. Template findings are candidates for analyst validation, not automatic proof of exploitability. Only run against explicitly authorized assets.


### 10.10.0 tool reliability updates

Gobuster now uses a smaller cross-version flag set and reports per-host launch diagnostics. Amass passive enumeration uses a bounded one-minute internal limit and preserves in-scope partial output when the subprocess watchdog expires. These changes are covered by adapter regression tests; live Kali execution still needs confirmation in your environment.
