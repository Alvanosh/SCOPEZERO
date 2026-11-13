# Installation on Kali Linux

## Requirements

- Kali Linux with Python 3 and `venv` support.
- Git (for cloning the repository).
- Network access to install Python dependencies.
- Optional external reconnaissance tools for workflows that invoke them.

## Install from GitHub

```bash
git clone <YOUR-GITHUB-REPOSITORY-URL>
cd SCOPEZERO/backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Start the application

```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Browse to `http://127.0.0.1:8000`. Stop the server with `Ctrl+C`.

## Local data and encryption key

The application creates its SQLite database locally when initialized. The database is deliberately ignored by Git. The authenticated test-identity feature creates a local Fernet vault key (`backend/.session_vault.key`) with restrictive permissions. Back up that key securely with the database if you need to retain encrypted test identities. Never add it to Git, screenshots, issue reports or shared archives.

## Optional external tools

Install and configure external tools separately according to their official documentation. The availability and output of those tools depend on the local environment. Do not assume a tool is installed merely because its adapter exists in SCOPEZERO.
