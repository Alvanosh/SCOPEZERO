"""Reliable subprocess execution for SCOPEZERO tool adapters.

Uses argument arrays (never a shell), process-group cleanup, bounded output,
and structured diagnostics so a timeout is not confused with zero findings.
"""
from __future__ import annotations
import os
import shutil
import signal
import subprocess
import time
from typing import Sequence

MAX_STDOUT = 500_000
MAX_STDERR = 40_000


def run_binary(name: str, args: Sequence[object], timeout: int = 120) -> dict:
    path = shutil.which(name)
    if not path:
        return {
            "available": False, "status": "not_installed", "returncode": None,
            "stdout": "", "stderr": "", "elapsed_seconds": 0.0,
            "error": f"{name} is not installed or not available on PATH.",
            "diagnostics": {"binary": name, "resolved_path": None, "timeout_seconds": timeout},
        }

    command = [path, *[str(x) for x in args]]
    started = time.monotonic()
    env = os.environ.copy()
    env.update({"NO_COLOR": "1", "CLICOLOR": "0", "TERM": "dumb"})
    proc = None
    stdout = ""
    stderr = ""
    status = "completed"
    error = None
    returncode = None
    try:
        proc = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", env=env,
            start_new_session=True, close_fds=True,
        )
        try:
            out, err = proc.communicate(timeout=max(1, int(timeout)))
            stdout, stderr, returncode = out or "", err or "", proc.returncode
            if returncode != 0:
                status = "execution_error"
                error = f"{name} exited with code {returncode}."
        except subprocess.TimeoutExpired:
            status = "timeout"
            error = f"{name} exceeded its {timeout}-second execution limit."
            # Kill the complete process group so child processes cannot outlive the job.
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                out, err = proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                out, err = proc.communicate()
            stdout, stderr = out or "", err or ""
            returncode = proc.returncode
    except FileNotFoundError:
        status = "not_installed"
        error = f"{name} executable disappeared before launch."
    except PermissionError as exc:
        status = "permission_error"
        error = f"Permission denied while launching {name}: {exc}"
    except OSError as exc:
        status = "execution_error"
        error = f"Could not launch {name}: {type(exc).__name__}: {exc}"
    elapsed = round(time.monotonic() - started, 3)
    stdout = stdout[-MAX_STDOUT:]
    stderr = stderr[-MAX_STDERR:]
    return {
        "available": True, "status": status, "returncode": returncode,
        "stdout": stdout, "stderr": stderr, "elapsed_seconds": elapsed,
        "error": error,
        "diagnostics": {
            "binary": name, "resolved_path": path, "timeout_seconds": int(timeout),
            "elapsed_seconds": elapsed, "returncode": returncode,
            "stdout_bytes_captured": len(stdout.encode("utf-8", "replace")),
            "stderr_bytes_captured": len(stderr.encode("utf-8", "replace")),
            "stderr_tail": stderr[-4000:], "stdout_tail": stdout[-2000:],
        },
    }
