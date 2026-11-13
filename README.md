# SCOPEZERO

**Version:** 10.7.0  
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
├── screenshots/
├── .env.example
├── .gitignore
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
