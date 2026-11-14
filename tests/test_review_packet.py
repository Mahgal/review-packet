"""Tests for review_packet.py (stdlib only, offline)."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import review_packet as m

SAMPLE_DIFF = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,2 +1,4 @@
 import os
+API_KEY = "sk-live-abcdefgh12345678"
+print("debug here")
 def main():
diff --git a/util.py b/util.py
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/util.py
@@ -0,0 +1,2 @@
+import subprocess
+subprocess.run(cmd, shell=True)
"""


class TestReviewPacket(unittest.TestCase):
    def test_parse_numstat(self):
        entries = m.parse_numstat("2\t1\tapp.py\n-\t-\tlogo.png\n")
        self.assertEqual(entries["app.py"].added, 2)
        self.assertEqual(entries["app.py"].deleted, 1)
        self.assertTrue(entries["logo.png"].is_binary)

    def test_scan_diff_lines_finds_secret_and_debug(self):
        hits = m.scan_diff_lines(SAMPLE_DIFF)
        app = hits.get("app.py", [])
        rules = {h["rule"] for h in app}
        self.assertIn("secret-like", rules)
        self.assertIn("debug-print", rules)
        self.assertTrue(any(h["severity"] == "high" for h in app))

    def test_scan_diff_lines_finds_shell_true(self):
        hits = m.scan_diff_lines(SAMPLE_DIFF)
        rules = {h["rule"] for h in hits.get("util.py", [])}
        self.assertIn("shell-true", rules)

    def test_packet_from_diff_file(self):
        with tempfile.TemporaryDirectory() as d:
            diff = Path(d) / "change.diff"
            diff.write_text(SAMPLE_DIFF)
            packet = m.packet_from_diff_file(diff)
        self.assertEqual(packet["summary"]["files_changed"], 2)
        self.assertEqual(packet["summary"]["high_severity_findings"], 1)
        self.assertEqual(packet["summary"]["lines_added"], 4)

    def test_large_file_rule(self):
        packet = m.build_packet(Path("."), "HEAD", "", "600\t0\tbig.py", "")
        self.assertEqual(packet["files"][0]["findings"][0]["rule"],
                         "large-file")

    def test_lockfile_rule(self):
        packet = m.build_packet(Path("."), "HEAD", "",
                                "10\t2\tpackage-lock.json", "")
        rules = [f["rule"] for f in packet["files"][0]["findings"]]
        self.assertIn("lockfile-churn", rules)

    def test_render_markdown_contains_table(self):
        packet = m.build_packet(Path("."), "HEAD~1", SAMPLE_DIFF,
                                "2\t0\tapp.py\n2\t0\tutil.py",
                                "M\tapp.py\nA\tutil.py")
        md = m.render_markdown(packet)
        self.assertIn("# Review packet", md)
        self.assertIn("app.py", md)
        self.assertIn("High-severity findings", md)

    def test_packet_from_real_git_repo(self):
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
                       GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
            subprocess.run(["git", "init", "-q", str(repo)], check=True, env=env)
            (repo / "a.py").write_text("x = 1\n")
            subprocess.run(["git", "-C", str(repo), "add", "."],
                           check=True, env=env)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "init"],
                           check=True, env=env)
            (repo / "a.py").write_text("x = 1\n# TODO fix later\n")
            (repo / "b.py").write_text("y = 2\n")
            packet = m.packet_from_repo(repo, "HEAD")
            self.assertEqual(packet["summary"]["files_changed"], 2)
            todo = [f for f in packet["files"]
                    for x in f["findings"] if x["rule"] == "todo-fixme"]
            self.assertEqual(len(todo), 1)

    def test_cli_exit_1_on_high_severity(self):
        with tempfile.TemporaryDirectory() as d:
            diff = Path(d) / "c.diff"
            diff.write_text(SAMPLE_DIFF)
            self.assertEqual(m.main(["--diff", str(diff)]), 1)
            self.assertEqual(m.main(["--diff", str(diff), "--no-fail"]), 0)

    def test_cli_json_output_parses(self):
        import io
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as d:
            diff = Path(d) / "c.diff"
            diff.write_text("diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
                            "@@ -1 +1 @@\n-x\n+y = 2\n")
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = m.main(["--diff", str(diff), "--format", "json"])
            self.assertEqual(code, 0)
            data = json.loads(buf.getvalue())
            self.assertEqual(data["summary"]["files_changed"], 1)


if __name__ == "__main__":
    unittest.main()
