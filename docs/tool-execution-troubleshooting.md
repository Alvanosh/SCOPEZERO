# Tool execution troubleshooting

SCOPEZERO 10.8.0 distinguishes successful empty results from execution failures.

## Status meanings

- `matches_found`: the tool completed and returned candidate observations.
- `no_matches`: the tool completed successfully but returned no observations.
- `timeout`: the configured execution deadline was reached; partial output may still be present.
- `not_installed`: the executable could not be resolved on the backend PATH.
- `permission_error`: the operating system denied process launch.
- `execution_error`: the process failed to launch or exited non-zero.
- `network_error`: an external intelligence service could not be reached.
- `preflight_incomplete`: the bounded DNS preflight could not inspect the full candidate set; narrow the asset set and retry.
- `partial_results`: some hosts returned results while others failed.

## Local checks

Run from the same shell/environment used to start Uvicorn:

```bash
command -v nmap nuclei httpx naabu amass subfinder katana dnsx gobuster
python -c "import shutil; names='nmap nuclei httpx naabu amass subfinder katana dnsx gobuster'.split(); [print(n, shutil.which(n)) for n in names]"
```

Restart Uvicorn after changing PATH or installing/updating tools. Tool execution diagnostics are visible in each run's Diagnostics and Raw result sections. Check the Uvicorn terminal for backend exceptions.

## Important

Target caps are deliberate safety and reliability limits. SCOPEZERO reports how many targets were omitted or not checked. A timeout or empty result is not evidence that a target is secure. Active checks require explicit authorization and must stay within the engagement scope.
