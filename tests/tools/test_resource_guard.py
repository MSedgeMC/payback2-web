import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("resource_guard", ROOT / "tools/resource_guard.py")
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)


class ResourceGuardTests(unittest.TestCase):
    def test_sparse_files_hardlinks_and_symlinks_are_accounted_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / "sparse"
            with file.open("wb") as stream:
                stream.seek(16 * 1024**2 - 1)
                stream.write(b"\0")
            os.link(file, root / "same-inode")
            (root / "external").symlink_to("/usr", target_is_directory=True)
            result = GUARD.account([root, root])
            self.assertGreaterEqual(result["apparent_bytes"], 16 * 1024**2)
            self.assertLess(result["apparent_bytes"], 17 * 1024**2)
            self.assertLess(result["allocated_bytes"], 1024**2)
            self.assertEqual(result["roots"][1]["inodes"], 0)

    def run_probe(self, arguments, code):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            cpus = ",".join(map(str, sorted(os.sched_getaffinity(0))[:2]))
            (ROOT / ".local/tmp").mkdir(parents=True, exist_ok=True)
            result = subprocess.run([sys.executable, str(ROOT / "tools/resource_guard.py"), "_monitor",
                                     "--report", str(report), "--cpus", cpus, "--mode", "monitored-rss",
                                     *arguments, "--", sys.executable, "-c", code],
                                    capture_output=True, text=True, timeout=5)
            return result, json.loads(report.read_text())

    def test_timeout_terminates_the_job_tree(self):
        result, report = self.run_probe(["--timeout", "0.25"], "import time; time.sleep(3)")
        self.assertEqual(result.returncode, 124)
        self.assertEqual(report["status"], "timeout")
        self.assertLess(report["elapsed_seconds"], 2)

    def test_aggregate_resident_limit_stops_a_memory_probe(self):
        result, report = self.run_probe(["--timeout", "3", "--rss-limit", str(32 * 1024**2)],
                                        "import time; memory=bytearray(64*1024**2); time.sleep(3)")
        self.assertEqual(result.returncode, 125)
        self.assertEqual(report["status"], "aggregate RSS limit")
        self.assertGreaterEqual(report["sampled_peak_rss_bytes"], 32 * 1024**2)


if __name__ == "__main__":
    unittest.main()
