"""migrate.py against real reports, and against each way a migration can go
wrong. Every gate rule is shown a report that breaks it and must fail.

    python3 -m unittest discover -s tests -v
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
MIGRATE = os.path.join(ROOT, "migration", "migrate.py")
DECISIONS = os.path.join(ROOT, "migration", "decisions.json")
TODAY = "2026-10-28"


class Migration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        shutil.copytree(os.path.join(FIXTURES, "snyk"), os.path.join(self.tmp, "snyk"))
        shutil.copytree(os.path.join(FIXTURES, "gitlab"), os.path.join(self.tmp, "gitlab"))
        shutil.copy(DECISIONS, os.path.join(self.tmp, "decisions.json"))

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def edit(self, rel, change):
        path = os.path.join(self.tmp, rel)
        with open(path) as f:
            data = json.load(f)
        change(data)
        with open(path, "w") as f:
            json.dump(data, f)

    def migrate(self, today=TODAY):
        out = os.path.join(self.tmp, "out")
        p = subprocess.run([sys.executable, "-I", MIGRATE, "--snyk", os.path.join(self.tmp, "snyk"),
                            "--gitlab", os.path.join(self.tmp, "gitlab"),
                            "--decisions", os.path.join(self.tmp, "decisions.json"),
                            "--out", out, "--today", today], capture_output=True, text=True)
        with open(os.path.join(out, "mapping.json")) as f:
            mapping = json.load(f)
        with open(os.path.join(out, "vulnerability-allowlist.yml")) as f:
            allowlist = f.read()
        return p.returncode, p.stdout, mapping, allowlist

    def outcome(self, mapping, snyk_id):
        return [r["outcome"] for r in mapping["snyk"] if r["id"] == snyk_id]

    # -- the run as it is ------------------------------------------------------

    def test_the_real_run_passes_the_gate(self):
        rc, out, mapping, _ = self.migrate()
        self.assertEqual(rc, 0, out)
        self.assertEqual(mapping["failures"], [])

    def test_each_planted_code_flaw_is_found_by_both(self):
        _, _, mapping, _ = self.migrate()
        for rule in ("python/Sqli", "python/CommandInjection", "python/Deserialization", "python/HardcodedNonCryptoSecret"):
            self.assertEqual(self.outcome(mapping, rule), ["matched"], rule)

    def test_one_snyk_finding_can_become_two_gitlab_findings(self):
        # GitLab reports the SQL injection twice, from two rule sets; both are
        # the same flaw, and neither is "new in GitLab".
        _, _, mapping, _ = self.migrate()
        row = [r for r in mapping["snyk"] if r["id"] == "python/Sqli"][0]
        self.assertEqual(len(row["gitlab"]), 2)

    def test_many_paths_to_one_package_are_one_finding(self):
        # Snyk lists a vulnerability once per dependency path (415 entries for
        # 106 issues in this image); counted per issue and installed package.
        _, _, mapping, _ = self.migrate()
        keys = [(r["id"], r.get("package")) for r in mapping["snyk"]]
        self.assertEqual(len(keys), len(set(keys)))

    def test_the_ignore_is_carried_with_its_expiry(self):
        _, _, mapping, allowlist = self.migrate()
        self.assertEqual(self.outcome(mapping, "SNYK-DEBIAN10-COREUTILS-317465"), ["ignore carried"])
        self.assertIn("CVE-2016-2781: coreutils", allowlist)
        self.assertIn("expires 2027-04-30", allowlist)

    # -- sabotage: each must fail the gate -------------------------------------

    def test_a_finding_lost_in_the_move_fails(self):
        # GitLab stops reporting the SQL injection: the migration lost it.
        self.edit("gitlab/gl-sast-report.json", lambda d: d.update(vulnerabilities=[
            v for v in d["vulnerabilities"] if v["location"].get("start_line") != 16]))
        rc, out, mapping, _ = self.migrate()
        self.assertEqual(rc, 1)
        self.assertIn("python/Sqli", out)
        self.assertEqual(self.outcome(mapping, "python/Sqli"), ["gap, undecided"])

    def test_a_lost_critical_package_finding_fails(self):
        # A critical package CVE both tools report, read from the run itself.
        _, _, mapping, _ = self.migrate()
        crit = next(r for r in mapping["snyk"] if r["kind"] in ("os", "app")
                    and r["severity"] == "critical" and r["outcome"] == "matched")
        gone = set(crit["cves"])
        self.edit("gitlab/gl-container-scanning-report.json", lambda d: d.update(vulnerabilities=[
            v for v in d["vulnerabilities"] if not gone & {i["value"] for i in v["identifiers"]}]))
        rc, out, mapping, _ = self.migrate()
        self.assertEqual(rc, 1, out)
        self.assertIn("%s (critical, %s): no GitLab finding" % (crit["id"], crit["package"]), out)

    def test_a_gap_without_a_decision_fails(self):
        self.edit("decisions.json", lambda d: d.update(accepted_gaps=[]))
        rc, out, mapping, _ = self.migrate()
        self.assertEqual(rc, 1)
        self.assertEqual(self.outcome(mapping, "python/XSS"), ["gap, undecided"])

    def test_a_decision_without_a_reason_fails(self):
        self.edit("decisions.json", lambda d: d["accepted_gaps"][0].update(reason=""))
        rc, out, _, _ = self.migrate()
        self.assertEqual(rc, 1)
        self.assertIn("without a reason is not a decision", out)

    def test_a_decision_left_behind_fails(self):
        self.edit("decisions.json", lambda d: d["accepted_gaps"].append(
            {"snyk_id": "python/PathTraversal", "file": "app.py", "line": 99, "reason": "no longer reported"}))
        rc, out, _, _ = self.migrate()
        self.assertEqual(rc, 1)
        self.assertIn("python/PathTraversal: a decision is recorded for a gap that no longer exists", out)

    def test_an_expired_ignore_is_not_carried(self):
        rc, out, mapping, allowlist = self.migrate(today="2027-05-01")
        self.assertEqual(rc, 1)
        self.assertEqual(self.outcome(mapping, "SNYK-DEBIAN10-COREUTILS-317465"), ["ignore expired"])
        self.assertNotIn("CVE-2016-2781", allowlist)

    def test_an_ignore_without_a_reason_is_not_carried(self):
        def strip(d):
            for v in d["filtered"]["ignore"]:
                for ig in v["filtered"]["ignored"]:
                    ig["reason"] = ""
        self.edit("snyk/snyk-container.json", strip)
        rc, out, mapping, allowlist = self.migrate()
        self.assertEqual(rc, 1)
        self.assertEqual(self.outcome(mapping, "SNYK-DEBIAN10-COREUTILS-317465"), ["ignore without a reason"])
        self.assertNotIn("CVE-2016-2781", allowlist)

    def test_an_unreadable_report_is_an_error_not_a_pass(self):
        os.remove(os.path.join(self.tmp, "gitlab", "gl-sast-report.json"))
        p = subprocess.run([sys.executable, "-I", MIGRATE, "--snyk", os.path.join(self.tmp, "snyk"),
                            "--gitlab", os.path.join(self.tmp, "gitlab"), "--out", os.path.join(self.tmp, "o")],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)
        self.assertIn("cannot read", p.stderr)


if __name__ == "__main__":
    unittest.main()
