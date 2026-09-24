"""Independent adoption checks for the canonical Engineering CI workflow (reads outputs and downloaded artifacts).

usage: check.py cases|enforced ARTIFACTS_DIR
Environment: NEEDS (toJSON(needs)); for "cases" also GH_TOKEN, REPO, SHA (code-scanning analyses of this commit).
Prints ::notice lines with the observed results and exits 1 on any mismatch. No retries of scanner work.
"""

import json
import os
import sys
import time
import urllib.request
from pathlib import Path

errors: list[str] = []
NV = {"authentication": "NOT VERIFIED", "session": "NOT VERIFIED", "authorization": "NOT VERIFIED"}

ALL_CASES = {  # case: (security, accessibility, performance, overall, enforced, expected job result)
    "clean": ("PASS", "PASS", "PASS", "PASS", False, "success"),
    "vulnerable": ("FAIL", "PASS", "PASS", "FAIL", False, "success"),
    "inaccessible": ("PASS", "FAIL", "PASS", "FAIL", False, "success"),
    "slow": ("PASS", "PASS", "FAIL", "FAIL", False, "success"),
    "all-fail": ("FAIL", "FAIL", "FAIL", "FAIL", False, "success"),
    "clean-enforced": ("PASS", "PASS", "PASS", "PASS", True, "success"),
}
ENFORCED_CASES = {"slow-enforced": ("PASS", "PASS", "FAIL", "FAIL", True, "failure")}

SEC_PREFIXES = ("P2-", "RT-", "AI-")

# Code-scanning category prefix per gate (engineering-ci.yml appends artifact_suffix "-<case>"), and the report file
# whose SARIF that gate uploads.
FAMILIES = {
    "security": ("vibe-code-engineering-security", Path("security-reports{sfx}/security.sarif")),
    "accessibility": ("vibe-code-engineering-quality-accessibility", Path("quality-reports{sfx}/accessibility.sarif")),
    "performance": ("vibe-code-engineering-quality-performance", Path("performance-reports{sfx}/performance.sarif")),
}
CASES_WORKFLOW = ".github/workflows/adoption-cases.yml"


def err(msg):
    errors.append(msg)
    print(f"::error title=adoption::{msg}")


def sarif_ids(path: Path):
    doc = json.loads(path.read_text(encoding="utf-8"))
    ids = [r.get("properties", {}).get("findingId", "") for run in doc["runs"] for r in run.get("results", [])]
    return doc, ids


def check_case(case, exp, needs, art):
    sec, acc, prf, overall, enforced, job_result = exp
    n = needs.get(case, {})
    o = n.get("outputs", {})
    got = (o.get("security_status"), o.get("quality_status"), o.get("performance_status"), o.get("overall"))
    if n.get("result") != job_result:
        err(f"{case}: reusable workflow result {n.get('result')!r}, expected {job_result!r}")
    if got != (sec, acc, prf, overall):
        err(f"{case}: statuses {got}, expected {(sec, acc, prf, overall)}")
    if (o.get("security_gate"), o.get("quality_gate"), o.get("performance_gate")) != (
            sec if sec != "NOT CONFIGURED" else "PASS", acc, prf):
        err(f"{case}: gate results {(o.get('security_gate'), o.get('quality_gate'), o.get('performance_gate'))}")
    if {k: o.get(k) for k in NV} != NV:
        err(f"{case}: coverage statuses {({k: o.get(k) for k in NV})}, expected all NOT VERIFIED")
    sfx = f"-{case}"
    files = {
        "security": art / f"security-reports{sfx}" / "security.sarif",
        "security_gate": art / f"security-reports{sfx}" / "security-gate.txt",
        "accessibility": art / f"quality-reports{sfx}" / "accessibility.sarif",
        "accessibility_gate": art / f"quality-reports{sfx}" / "quality-gate.txt",
        "performance": art / f"performance-reports{sfx}" / "performance.sarif",
        "performance_gate": art / f"performance-reports{sfx}" / "performance-gate.txt",
        "summary": art / f"engineering-reports{sfx}" / "engineering-summary.json",
    }
    for k, p in files.items():
        if not p.is_file() or p.stat().st_size == 0:
            err(f"{case}: missing {k} output {p.relative_to(art)} (gate did not run or upload)")
    if any(not p.is_file() for p in files.values()):
        return
    sdoc, sids = sarif_ids(files["security"])
    adoc, aids = sarif_ids(files["accessibility"])
    pdoc, pids = sarif_ids(files["performance"])
    if any(not i.startswith(SEC_PREFIXES) for i in sids):
        err(f"{case}: non-security IDs in security SARIF: {[i for i in sids if not i.startswith(SEC_PREFIXES)]}")
    if any(not i.startswith("Q-A11Y-") for i in aids):
        err(f"{case}: non Q-A11Y IDs in accessibility SARIF")
    if any(not i.startswith("Q-PERF-") for i in pids):
        err(f"{case}: non Q-PERF IDs in performance SARIF")
    for name, doc in (("accessibility", adoc), ("performance", pdoc)):
        if "security-severity" in json.dumps(doc):
            err(f"{case}: security-severity present in {name} SARIF")
    for name, status, ids in (("security", sec, sids), ("accessibility", acc, aids), ("performance", prf, pids)):
        if status == "FAIL" and not ids:
            err(f"{case}: {name} FAIL but its SARIF has no results")
    # The report artifacts keep the tools' original SARIF; only the upload copy carries the per-case category.
    autos = {d["runs"][0].get("automationDetails", {}).get("id") for d in (adoc, pdoc)}
    if autos != {"vibe-code-engineering/quality/accessibility/", "vibe-code-engineering/quality/performance/"}:
        err(f"{case}: quality SARIF automation ids {autos}")
    summary = json.loads(files["summary"].read_text(encoding="utf-8"))
    if summary.get("verification") != NV:
        err(f"{case}: summary verification {summary.get('verification')}")
    if summary.get("enforced") is not enforced:
        err(f"{case}: summary enforced={summary.get('enforced')}, expected {enforced}")
    if summary.get("security", {}).get("runtime") != "NOT RUN":
        err(f"{case}: Phase 3 runtime {summary.get('security', {}).get('runtime')}, expected NOT RUN (no target)")
    rel = summary.get("performance", {}).get("timing_reliability")
    print(f"::notice title=case {case}::" + json.dumps({
        "security": sec, "accessibility": acc, "performance": prf, "overall": overall, "enforced": enforced,
        "job": n.get("result"), "security_ids": sorted({i.rsplit('-', 1)[0] for i in sids}),
        "a11y_ids": len(aids), "perf_ids": len(pids), "perf_failing_rules": sorted({
            r["ruleId"] for r in pdoc["runs"][0]["results"] if r.get("level") == "error"}),
        "timing_reliability": rel, "verification": summary.get("verification")}, sort_keys=True))


# --- code scanning -------------------------------------------------------------------------------------------------

def canonical_category(category: str) -> str:
    """Category as GitHub keys it: upload-sarif stores category X as runs[].automationDetails.id "X/" and the analyses
    API may report either "X" or "X/". Exactly one trailing "/" is dropped; nothing else is normalised, so two
    categories that differ in any other character stay distinct."""
    return category[:-1] if category.endswith("/") else category


def expected_categories(cases) -> dict[str, tuple[str, str]]:
    """Canonical category -> (case, gate) for every expected upload. Any two expected uploads that would share a
    canonical category (across gates or across cases) are reported as a collision."""
    owners: dict[str, list[tuple[str, str]]] = {}
    for case in cases:
        for gate, (prefix, _) in FAMILIES.items():
            owners.setdefault(canonical_category(f"{prefix}-{case}"), []).append((case, gate))
    for cat, who in owners.items():
        if len(who) > 1:
            err(f"expected code-scanning category collision: {cat!r} shared by {who}")
    return {cat: who[0] for cat, who in owners.items()}


def sarif_expectations(cases, art: Path) -> dict[tuple[str, str], tuple[str, int]]:
    """(case, gate) -> (tool driver name, result count) of the SARIF that gate uploaded (from the report artifact)."""
    out = {}
    for case in cases:
        for gate, (_, rel) in FAMILIES.items():
            p = art / str(rel).format(sfx=f"-{case}")
            if p.is_file():
                doc = json.loads(p.read_text(encoding="utf-8"))
                out[(case, gate)] = (doc["runs"][0]["tool"]["driver"]["name"],
                                     sum(len(r.get("results", [])) for r in doc["runs"]))
    return out


def check_code_scanning(analyses, sha, cases, sarif_exp) -> int:
    """Checks the code-scanning analyses of commit `sha`. Every expected (case, gate) must have its own canonical
    category holding only analyses of that gate's tool with that case's result count; no analysis of another workflow
    may land in one of those categories, and no adoption-cases analysis may use any other category. Returns the
    number of expected categories that are present and correct."""
    want = expected_categories(cases)
    got: dict[str, list[dict]] = {}
    for a in analyses:
        if a.get("commit_sha") == sha:
            got.setdefault(canonical_category(a.get("category", "")), []).append(a)
    ok = 0
    for cat, (case, gate) in sorted(want.items()):
        found = got.get(cat, [])
        if not found:
            err(f"code-scanning analysis missing for {case}/{gate}: category {cat!r}")
            continue
        tool, count = sarif_exp.get((case, gate), (None, None))
        bad = False
        for a in found:
            key, name, n = a.get("analysis_key", ""), a.get("tool", {}).get("name"), a.get("results_count")
            if not key.startswith(f"{CASES_WORKFLOW}:"):
                err(f"code-scanning category collision: {cat!r} ({case}/{gate}) also used by {key!r}")
                bad = True
            elif name != tool or n != count or a.get("error"):
                err(f"code-scanning {cat!r} ({case}/{gate}): tool {name!r} with {n} result(s)"
                    f"{' error ' + repr(a['error']) if a.get('error') else ''}; expected {tool!r} with {count}")
                bad = True
        ok += not bad
    for cat, found in sorted(got.items()):
        ours = [a for a in found if a.get("analysis_key", "").startswith(f"{CASES_WORKFLOW}:")]
        if cat not in want and ours:
            err(f"unexpected code-scanning category {cat!r} for this commit from {CASES_WORKFLOW} "
                f"({len(ours)} analysis/analyses) - uploads are not isolated per case and gate")
    return ok


def fetch_analyses(repo: str, token: str) -> list[dict]:
    out: list[dict] = []
    for page in range(1, 11):
        req = urllib.request.Request(
            f"https://api.github.com/repos/{repo}/code-scanning/analyses?per_page=100&page={page}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            batch = json.load(resp)
        out += batch
        if len(batch) < 100:
            break
    return out


def main(argv) -> int:
    mode, art = argv[1], Path(argv[2])
    needs = json.loads(os.environ["NEEDS"])
    cases = ENFORCED_CASES if mode == "enforced" else ALL_CASES
    for case, exp in cases.items():
        check_case(case, exp, needs, art)

    if mode == "cases":
        sha, sarif_exp = os.environ["SHA"], sarif_expectations(cases, art)
        want = {canonical_category(f"{p}-{c}") for c in cases for p, _ in FAMILIES.values()}
        analyses: list[dict] = []
        for _ in range(12):   # upload processing is asynchronous; wait up to ~2 minutes (not a retry of any scan)
            analyses = fetch_analyses(os.environ["REPO"], os.environ["GH_TOKEN"])
            if want <= {canonical_category(a.get("category", "")) for a in analyses if a.get("commit_sha") == sha}:
                break
            time.sleep(10)
        ok = check_code_scanning(analyses, sha, cases, sarif_exp)
        print(f"::notice title=code scanning::{ok}/{len(want)} expected categories present, distinct and correct")

    print(f"::notice title=adoption {mode}::{'PASS' if not errors else 'FAIL'} ({len(errors)} problem(s))")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
