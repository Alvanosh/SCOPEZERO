# Architecture overview

SCOPEZERO 10.8.0 is organized as a local web application:

- `backend/app/main.py` exposes the FastAPI application and HTTP routes.
- `backend/app/database.py` initializes and accesses the local SQLite database.
- `backend/app/pipeline.py` and `backend/app/worker.py` coordinate assessment workflows.
- `backend/app/engines/` contains discovery, reconnaissance, assessment, intelligence and investigation logic.
- `frontend/index.html` contains the current browser interface.

The backend stores engagement and scan state locally. Assessment output, evidence and credentials can be sensitive; keep local runtime state out of source control. The current release is intended for a single local operator and is not a hardened multi-user service.

## Data lifecycle

1. The operator creates an engagement and defines authorized scope/exclusions.
2. Assessment workflows operate against assets in that scope.
3. Observations and findings are stored in the local database.
4. Analysts validate investigation signals and associate evidence.
5. Findings can be tracked, compared and included in reports.

Scope checks and individual module restrictions are implemented in the application, but they do not replace human authorization and engagement oversight.


## Tool execution lifecycle

Command adapters use `engines/process.py`, which resolves binaries through the backend process PATH, launches argument arrays without a shell, captures bounded stdout/stderr, records elapsed time and exit code, and terminates the full child process group when a timeout occurs. Adapters map tool outcomes to distinct states (`no_matches`, `timeout`, `permission_error`, `execution_error`, `network_error`, and others). Target caps and preflight omissions are returned explicitly.
