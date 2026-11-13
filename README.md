# SCOPEZERO

### REDLINE — Advanced Security Assessment & Investigation Platform

**Version:** 14.0.0  
**Project:** Security assessment, reconnaissance and web application testing workspace  
**Platform:** Linux / Kali Linux  
**Status:** Active Development

SCOPEZERO is a modular security assessment platform designed to bring reconnaissance, attack-surface discovery, vulnerability intelligence, web application testing, HTTP traffic inspection and evidence management into one unified workspace.

Built for security researchers, penetration testers and cybersecurity enthusiasts, SCOPEZERO combines local security tools with an integrated web testing environment.

> **Authorization required:** SCOPEZERO must only be used against systems for which you have explicit permission to perform security testing.

---

## Core capabilities

### 1. Reconnaissance and attack-surface discovery
- Domain and subdomain discovery.
- DNS and infrastructure intelligence.
- HTTP service discovery and probing.
- Network and port assessment.
- Technology and service observations.

### 2. Offensive security toolkit
- Nmap-based network assessment.
- Nuclei template-based vulnerability checks.
- Gobuster directory and content discovery.
- Subfinder and HTTPX reconnaissance pipeline.
- Technology fingerprinting and infrastructure identification.
- Configurable assessment workflows.

### 3. SCOPEZERO Web Suite
An integrated environment for authorized web application security testing.

- HTTP/HTTPS traffic inspection.
- Browser traffic capture integration.
- Intercept, forward and drop controls.
- HTTP Repeater for editable requests.
- Intruder-style controlled payload testing.
- Request and response inspection.
- Target sitemap and endpoint overview.
- Custom wordlist support for bounded fuzzing.

### 4. Browser Capture Extension
The SCOPEZERO Browser Capture extension connects supported browsers to the local assessment backend.

Features:
- Browser request capture.
- In-scope traffic filtering.
- Request metadata collection.
- Integration with the Web Suite.

### 5. Vulnerability intelligence
- CVE correlation.
- CVSS and EPSS enrichment.
- CISA KEV intelligence.
- Technology and service observations.
- Evidence-based vulnerability review.

### 6. API security assessment
- API endpoint inventory.
- Authentication and authorization review.
- Identity-based response comparison.
- API access-control observation records.

### 7. Evidence and reporting
- Centralized assessment evidence.
- Finding management.
- Investigation notes.
- Assessment history.
- Reporting workflows.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/Alvanosh/SCOPEZERO.git
cd SCOPEZERO
```

Create a virtual environment:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Configure environment variables:

```bash
cp ../.env.example .env
nano .env
```

Set your own local secrets and configuration values. Never publish the populated `.env` file.

Start the application using the project's configured startup instructions.

---

## Browser extension installation

1. Open `brave://extensions` or `chrome://extensions`.
2. Enable Developer mode.
3. Select **Load unpacked**.
4. Choose the `browser-extension` directory.
5. Configure the backend URL and assessment settings.
6. Use the extension with an authorized assessment session.

For HTTPS interception, use the dedicated assessment browser profile and the SCOPEZERO local CA certificate. Remove the certificate after testing.

---

## Project structure

```text
SCOPEZERO/
├── backend/
│   ├── app/
│   │   ├── engines/
│   │   └── main.py
│   └── requirements.txt
├── browser-extension/
├── frontend/
├── docs/
├── tests/
├── .env.example
├── .gitignore
├── CHANGELOG.md
├── CONTRIBUTING.md
├── LICENSE
└── README.md
```

---

## Security and responsible use

- Use only against explicitly authorized targets.
- Keep API keys, tokens and credentials outside source control.
- Never publish database files or assessment evidence containing sensitive data.
- Protect local interception CA private keys.
- Use a dedicated browser profile for HTTPS interception.
- Review engagement scope before running active assessment tools.

## Development

SCOPEZERO is under active development. Features, integrations and assessment workflows are continuously evolving.

Contributions, bug reports and responsible security feedback are welcome.

## License

MIT License. See [LICENSE](LICENSE) for details.

---

**SCOPEZERO // REDLINE**

*Reconnaissance. Inspection. Intelligence. Assessment.*
