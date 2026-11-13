import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.app.engines.process import run_binary


class ProcessRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.bin = Path(self.tmp.name)
        self.old_path = os.environ.get("PATH", "")

    def tearDown(self):
        self.tmp.cleanup()

    def script(self, name, body):
        p = self.bin / name
        p.write_text("#!/usr/bin/env python3\n" + body)
        p.chmod(0o755)
        return p

    def run_with_path(self, name, *args, timeout=3):
        with patch.dict(os.environ, {"PATH": str(self.bin) + os.pathsep + self.old_path}):
            return run_binary(name, args, timeout=timeout)

    def test_success_captures_stdout_and_stderr(self):
        self.script("fakeok", "import sys; print('hello'); print('note', file=sys.stderr)\n")
        result = self.run_with_path("fakeok")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["returncode"], 0)
        self.assertIn("hello", result["stdout"])
        self.assertIn("note", result["stderr"])

    def test_nonzero_exit_is_execution_error(self):
        self.script("fakebad", "import sys; print('bad', file=sys.stderr); sys.exit(7)\n")
        result = self.run_with_path("fakebad")
        self.assertEqual(result["status"], "execution_error")
        self.assertEqual(result["returncode"], 7)

    def test_timeout_is_reported_and_process_is_stopped(self):
        self.script("fakeslow", "import time; print('started', flush=True); time.sleep(10)\n")
        result = self.run_with_path("fakeslow", timeout=1)
        self.assertEqual(result["status"], "timeout")
        self.assertIn("started", result["stdout"])
        self.assertIsNotNone(result["diagnostics"]["elapsed_seconds"])

    def test_missing_binary_is_not_installed(self):
        result = self.run_with_path("not-a-real-scopezero-binary")
        self.assertEqual(result["status"], "not_installed")
        self.assertFalse(result["available"])


if __name__ == "__main__":
    unittest.main()

class NucleiAdapterTests(unittest.TestCase):
    def test_nuclei_uses_http_misconfig_and_vuln_tags_in_batches(self):
        import json
        from unittest.mock import patch
        from backend.app.engines import offensive
        calls = []
        def fake_run(name, args, timeout=180):
            calls.append((name, list(args), timeout))
            return {"available": True, "status": "completed", "returncode": 0,
                    "stdout": json.dumps({"host":"https://example.test", "template-id":"http-test",
                        "info":{"name":"HTTP test", "severity":"info", "reference":[]}}) + "\n",
                    "stderr":"", "elapsed_seconds":0.01, "error":None}
        with patch.object(offensive, "public_hosts", return_value=(
                [f"h{i}.example.test" for i in range(11)], 0, 0)), \
             patch.object(offensive.shutil, "which", return_value="/usr/bin/nuclei"), \
             patch.object(offensive, "run_tool", side_effect=fake_run):
            result = offensive.nuclei_scan([f"h{i}.example.test" for i in range(11)])
        self.assertEqual(result["status"], "matches_found")
        self.assertEqual(result["total_batches"], 3)
        self.assertTrue(all(c[0] == "nuclei" and c[2] == 120 for c in calls))
        joined = " ".join(str(x) for x in calls[0][1])
        self.assertIn("http,misconfig,vuln,exposure,ssl", joined)
        self.assertIn("intrusive", joined)

class GobusterAmassAdapterTests(unittest.TestCase):
    def test_gobuster_uses_compatible_flags_and_parses_standard_output(self):
        from backend.app.engines import offensive
        calls = []
        def fake_run(name, args, timeout=180):
            calls.append((name, list(args), timeout))
            return {"available": True, "status": "completed", "returncode": 0,
                    "stdout": "/admin (Status: 200) [Size: 42]\\n", "stderr": "",
                    "elapsed_seconds": 0.1, "error": None}
        with patch.object(offensive, "public_hosts", return_value=(["example.test"], 0, 0)), \
             patch.object(offensive.shutil, "which", return_value="/usr/bin/gobuster"), \
             patch.object(offensive, "run_tool", side_effect=fake_run):
            result = offensive.gobuster_scan(["example.test"])
        self.assertEqual(result["status"], "matches_found")
        self.assertEqual(result["results"][0]["path"], "/admin")
        self.assertIn("--timeout", calls[0][1])
        self.assertNotIn("--no-progress", calls[0][1])
        self.assertNotIn("--no-error", calls[0][1])

    def test_gobuster_surfaces_launch_error_instead_of_no_matches(self):
        from backend.app.engines import offensive
        with patch.object(offensive, "public_hosts", return_value=(["example.test"], 0, 0)), \
             patch.object(offensive.shutil, "which", return_value="/usr/bin/gobuster"), \
             patch.object(offensive, "run_tool", return_value={"available": True, "status": "execution_error",
                 "returncode": 2, "stdout": "", "stderr": "unknown flag", "error": "exit code 2"}):
            result = offensive.gobuster_scan(["example.test"])
        self.assertEqual(result["status"], "execution_error")
        self.assertIn("unknown flag", result["host_errors"][0]["stderr"])

    def test_amass_retains_partial_results_on_timeout(self):
        from backend.app.engines import recon
        with patch.object(recon.shutil, "which", return_value="/usr/bin/amass"), \
             patch.object(recon, "run_tool", return_value={"available": True, "status": "timeout",
                 "returncode": -15, "stdout": "www.example.com\napi.example.com\n", "stderr": "provider slow",
                 "error": "timeout", "diagnostics": {}, "elapsed_seconds": 95}):
            result = recon.amass_passive("example.com")
        self.assertEqual(result["status"], "partial_results")
        self.assertEqual(result["count"], 2)
