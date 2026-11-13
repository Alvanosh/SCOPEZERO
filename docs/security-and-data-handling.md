# Security and data handling

SCOPEZERO can process highly sensitive security assessment information. Treat the workstation, database, evidence and encryption key as confidential.

## Never commit

- `backend/.session_vault.key` or any other private key.
- `.env` files containing real values, API keys, tokens, passwords or cookies.
- SQLite databases containing engagement or client data.
- Evidence attachments, request/response captures, exports or reports from real assessments.
- Virtual environments, caches, logs or local backups.

The repository `.gitignore` excludes common paths and file types, but it is not a substitute for reviewing `git status`, staged files and the full commit history before pushing.

## Authenticated test identities

Stored request headers are encrypted at rest using a local Fernet key. The key is created locally and excluded from this repository. Keep the key private and back it up securely alongside the matching database. If the key is lost, encrypted identity data cannot be recovered. Rotate credentials when required and avoid using production user credentials for testing.

## Before every push

```bash
git status --short
git diff --cached --name-only
```

Review every staged file. Search for secrets and sensitive data. If a secret was committed, revoke/rotate it immediately; deleting it in a later commit is not sufficient. Consider the secret exposed.

## Deployment warning

The current release is designed for local use, bound to `127.0.0.1`. Do not deploy it as a public service without adding authentication, TLS, authorization boundaries, secure configuration, rate limits, audit protections and a production secrets-management approach.
