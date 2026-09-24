"""Self-tests of the code-scanning category assertions in check.py (no network).

usage: python3 -m unittest discover -s .github/adoption -p "test_*.py"
"""

import contextlib
import io
import unittest

import check

SHA = "a" * 40
TOOLS = {"security": "phase2-security-scanner", "accessibility": "quality-ci-accessibility",
         "performance": "quality-ci-performance"}
JOBS = {"security": "security", "accessibility": "quality", "performance": "performance"}


def count(case):
    return 0 if case.startswith("clean") else 1


def sarif_exp(cases):
    return {(c, g): (TOOLS[g], count(c)) for c in cases for g in check.FAMILIES}


def analyses(cases, slash=True, over=None):
    """One analysis per (case, gate) as GitHub reports it after the upload-boundary fix."""
    out = []
    for c in cases:
        for g, (prefix, _) in check.FAMILIES.items():
            a = {"commit_sha": SHA, "category": f"{prefix}-{c}" + ("/" if slash else ""),
                 "analysis_key": f"{check.CASES_WORKFLOW}:{JOBS[g]}", "tool": {"name": TOOLS[g]},
                 "results_count": count(c), "error": ""}
            a.update((over or {}).get((c, g), {}))
            out.append(a)
    return out


class CodeScanning(unittest.TestCase):
    def setUp(self):
        check.errors.clear()

    def run_check(self, found, cases=check.ALL_CASES):
        with contextlib.redirect_stdout(io.StringIO()):
            ok = check.check_code_scanning(found, SHA, cases, sarif_exp(cases))
        return ok, list(check.errors)

    def test_canonical_category(self):
        self.assertEqual(check.canonical_category("x-clean/"), "x-clean")
        self.assertEqual(check.canonical_category("x-clean"), "x-clean")
        self.assertEqual(check.canonical_category("x-clean//"), "x-clean/")   # only one "/" is GitHub's
        self.assertNotEqual(check.canonical_category("x-clean/"), check.canonical_category("x-clean-enforced/"))

    def test_expected_categories_distinct_per_gate_and_case(self):
        want = check.expected_categories(check.ALL_CASES)
        self.assertEqual(len(want), len(check.ALL_CASES) * len(check.FAMILIES))
        self.assertEqual(check.errors, [])
        self.assertEqual({g for (_, g) in want.values()}, set(check.FAMILIES))

    def test_expected_category_collision_is_reported(self):
        with contextlib.redirect_stdout(io.StringIO()):
            check.expected_categories({"clean": None, "clean/": None})
        self.assertTrue(any("expected code-scanning category collision" in e for e in check.errors))

    def test_trailing_slash_accepted(self):
        ok, errs = self.run_check(analyses(check.ALL_CASES, slash=True))
        self.assertEqual((ok, errs), (18, []))

    def test_without_trailing_slash_accepted(self):
        ok, errs = self.run_check(analyses(check.ALL_CASES, slash=False))
        self.assertEqual((ok, errs), (18, []))

    def test_other_commits_ignored(self):
        found = analyses(check.ALL_CASES) + [dict(a, commit_sha="b" * 40, category="vibe-code-engineering/phase2")
                                             for a in analyses(check.ALL_CASES)]
        self.assertEqual(self.run_check(found), (18, []))

    def test_missing_analysis(self):
        found = [a for a in analyses(check.ALL_CASES) if a["category"] != "vibe-code-engineering-security-slow/"]
        ok, errs = self.run_check(found)
        self.assertEqual(ok, 17)
        self.assertTrue(any("missing for slow/security" in e for e in errs))

    def test_legacy_shared_categories_fail(self):
        """The pre-fix behaviour: every case of a gate uploaded under the tool's own automationDetails.id."""
        legacy = {"security": "vibe-code-engineering/phase2", "accessibility": "vibe-code-engineering/quality/accessibility",
                  "performance": "vibe-code-engineering/quality/performance"}
        found = [dict(a, category=legacy[g]) for a, (c, g) in
                 zip(analyses(check.ALL_CASES), [(c, g) for c in check.ALL_CASES for g in check.FAMILIES])]
        ok, errs = self.run_check(found)
        self.assertEqual(ok, 0)
        self.assertEqual(sum("missing for" in e for e in errs), 18)
        self.assertEqual(sum("unexpected code-scanning category" in e for e in errs), 3)

    def test_gate_collision_fails(self):
        """Accessibility SARIF uploaded under the security category of the same case."""
        found = analyses(check.ALL_CASES, over={("vulnerable", "accessibility"): {
            "category": "vibe-code-engineering-security-vulnerable/"}})
        ok, errs = self.run_check(found)
        self.assertLess(ok, 18)
        self.assertTrue(any("missing for vulnerable/accessibility" in e for e in errs))
        self.assertTrue(any("vibe-code-engineering-security-vulnerable" in e and "quality-ci-accessibility" in e
                            for e in errs))

    def test_case_collision_fails(self):
        """Two cases uploaded under one category (e.g. a repeated artifact_suffix)."""
        found = analyses(check.ALL_CASES, over={("clean-enforced", "performance"): {
            "category": "vibe-code-engineering-quality-performance-slow"}})
        ok, errs = self.run_check(found)
        self.assertLess(ok, 18)
        self.assertTrue(any("missing for clean-enforced/performance" in e for e in errs))
        self.assertTrue(any("quality-performance-slow" in e and "with 0 result(s)" in e for e in errs))
        self.assertEqual(ok, 16)   # clean-enforced/performance missing, slow/performance polluted

    def test_foreign_workflow_in_case_category_fails(self):
        found = analyses(check.ALL_CASES) + [dict(analyses(["clean"])[0],
                                                  analysis_key=".github/workflows/engineering-ci.yml:security")]
        ok, errs = self.run_check(found)
        self.assertEqual(ok, 17)
        self.assertTrue(any("category collision" in e and "engineering-ci.yml" in e for e in errs))

    def test_other_workflows_own_categories_ignored(self):
        """engineering-ci (no suffix) and adoption-enforced (-slow-enforced) upload for the same commit."""
        extra = [dict(a, category=a["category"].replace("-clean/", "/"), analysis_key=".github/workflows/engineering-ci.yml:x")
                 for a in analyses(["clean"])]
        extra += [dict(a, analysis_key=".github/workflows/adoption-enforced.yml:x") for a in analyses(["slow-enforced"])]
        self.assertEqual(self.run_check(analyses(check.ALL_CASES) + extra), (18, []))

    def test_wrong_result_count_fails(self):
        found = analyses(check.ALL_CASES, over={("inaccessible", "accessibility"): {"results_count": 0}})
        ok, errs = self.run_check(found)
        self.assertEqual(ok, 17)
        self.assertTrue(any("inaccessible/accessibility" in e for e in errs))

    def test_upload_error_fails(self):
        found = analyses(check.ALL_CASES, over={("slow", "performance"): {"error": "processing failed"}})
        ok, errs = self.run_check(found)
        self.assertEqual(ok, 17)
        self.assertTrue(any("processing failed" in e for e in errs))


if __name__ == "__main__":
    unittest.main()
