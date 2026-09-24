# Vibe Adoption Test

Fresh external adoption test for [GeoRobert630/vibe-code-engineering](https://github.com/GeoRobert630/vibe-code-engineering):
a new project adopting the complete system through the **canonical workflow** only.

- `.github/workflows/engineering-ci.yml` - unchanged copy of `tools/engineering-ci/examples/github-actions-engineering-ci.yml`
  at `70d52f8` (SARIF upload-boundary fix, validated here before release; previous release `engineering-ci-v1.1` =
  `62461a6`). It pins released tooling: Security `bd71c46` (`security-baseline-v1`),
  Accessibility `fa816aa` (`quality-ci-v1.1`), Performance `c6b82c0` (`quality-ci-v1.2`).
- `.github/workflows/adoption-cases.yml` - calls it once per case with real tools and checks every result
  (`.github/adoption/check.py`, self-tested by `.github/adoption/test_check.py`): outputs, report artifacts, SARIF
  namespaces, code-scanning categories, coverage statuses. Each case and gate must upload to its own code-scanning
  category `vibe-code-engineering-{security,quality-accessibility,quality-performance}-<case>`; GitHub keys it by
  `runs[].automationDetails.id` = category + `/`, so the check compares categories with exactly one trailing `/`
  dropped and still fails on any missing, shared or foreign category.
- `.github/workflows/adoption-enforced.yml` - the slow case with the default `enforce: true`; **expected to FAIL**
  (performance FAIL blocks final enforcement while all three gates still run).

| Case | Security | Accessibility | Performance | Final |
|---|---|---|---|---|
| `cases/clean` | PASS | PASS | PASS | PASS |
| `cases/vulnerable` | FAIL | PASS | PASS | FAIL |
| `cases/inaccessible` | PASS | FAIL | PASS | FAIL |
| `cases/slow` (page `/slow.html`) | PASS | PASS | FAIL | FAIL |
| `cases/all-fail` (pages `/ /slow.html`) | FAIL | FAIL | FAIL | FAIL |

Fixtures: clean app (`vibe-security-test` `e3aae91`), SQL-injection fixture (`vibe-security-test` `e96b3cc`),
accessibility fixtures (`tools/quality-ci/fixtures` at `quality-ci-v1.1`), performance SLOW fixture
(`tools/quality-ci/fixtures/performance` at `quality-ci-v1.2`). They are **intentionally vulnerable / inaccessible /
slow and exist only for CI testing**; no secrets. No runtime target is configured, so Authentication, Session and
Authorization are NOT VERIFIED.

The push-triggered `engineering-ci` run scans the whole repository with enforcement on; the repository contains the
vulnerable fixtures and has no quality target, so that run is **expected to FAIL** (Security FAIL; Accessibility and
Performance NOT CONFIGURED).
