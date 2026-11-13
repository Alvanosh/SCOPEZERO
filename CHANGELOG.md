# Changelog

## 10.8.0 — Tool Execution Reliability

- Added a shared subprocess runner with safe argument-array execution, process-group termination, bounded output capture, elapsed-time measurement and structured diagnostics.
- Standardized command execution outcomes so timeouts, permission errors, launch errors and successful empty results are not conflated.
- Updated Nmap and Nuclei to use bounded target sets and report omitted targets.
- Updated Naabu to TCP connect mode for environments where raw-packet privileges are unavailable.
- Tuned httpx concurrency and request rate, and capped very large target batches.
- Parallelized and bounded public-host DNS preflight checks.
- Added structured diagnostics to tool results and improved UI status labels.
- Added regression tests for successful execution, non-zero exit, timeout cleanup and missing binaries.

### Validation

- Python compilation passed.
- Four subprocess runner tests passed.
- Ten inline frontend JavaScript blocks passed Node syntax checks.
- FastAPI application import passed.

No live external assessment was performed as part of this release.

## 10.9.0 — HTTP-focused Nuclei template coverage

- Nuclei now selects HTTP, misconfiguration, vulnerability, exposure and TLS template tags.
- Excludes intrusive, DoS, fuzzing, brute-force, headless, code, file, network and workflow template classes.
- Splits up to 25 eligible in-scope hosts into batches of five with per-batch timeout and diagnostics.
- Reports partial completion distinctly from a clean no-match result; findings remain analyst-validation candidates.

## 10.10.0 — Gobuster & Amass reliability
- Simplified Gobuster arguments to broadly supported Gobuster v3 flags; removed optional flags that vary between packaged builds.
- Added per-host Gobuster execution diagnostics and retained parseable output even when a host run exits non-zero.
- Improved Gobuster status classification so launch errors are not reported as empty successful scans.
- Bounded Amass passive enumeration to a one-minute internal limit and a capped subprocess watchdog.
- Preserved in-scope Amass output as partial results when the outer watchdog expires.
- Added regression tests for Gobuster argument compatibility, launch errors and Amass partial-timeout output.
