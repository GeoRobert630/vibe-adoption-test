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

mode, art = sys.argv[1], Path(sys.argv[2])
needs = json.loads(os.environ["NEEDS"])
errors: list[str] = []
NV = {"authentication": "NOT VERIFIED", "session": "NOT VERIFIED", "authorization": "NOT VERIFIED"}

CASES = {  # case: (security, accessibility, performance, overall, enforced, expected job result)
    "clean": ("PASS", "PASS", "PASS", "PASS", False, "success"),
    "vulnerable": ("FAIL", "PASS", "PASS", "FAIL", False, "success"),
    "inaccessible": ("PASS", "FAIL", "PASS", "FAIL", False, "success"),
    "slow": ("PASS", "PASS", "FAIL", "FAIL", False, "success"),
    "all-fail": ("FAIL", "FAIL", "FAIL", "FAIL", False, "success"),
    "clean-enforced": ("PASS", "PASS", "PASS", "PASS", True, "success"),
}
if mode == "enforced":
    CASES = {"slow-enforced": ("PASS", "PASS", "FAIL", "FAIL", True, "failure")}

SEC_PREFIXES = ("P2-", "RT-", "AI-")


def err(msg):
    errors.append(msg)
    print(f"::error title=adoption::{msg}")


def sarif_ids(path: Path):
    doc = json.loads(path.read_text(encoding="utf-8"))
    ids = [r.get("properties", {}).get("findingId", "") for run in doc["runs"] for r in run.get("results", [])]
    return doc, ids


def check_case(case, exp):
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


for case, exp in CASES.items():
    check_case(case, exp)

if mode == "cases":
    # All three SARIF families uploaded for this commit under distinct code-scanning categories.
    want = {f"{fam}-{c}" for c in CASES for fam in ("vibe-code-engineering-security", "vibe-code-engineering-quality-accessibility",
                                                    "vibe-code-engineering-quality-performance")}
    cats: set[str] = set()
    for _ in range(12):   # upload processing is asynchronous; wait up to ~2 minutes (not a retry of any scan)
        req = urllib.request.Request(f"https://api.github.com/repos/{os.environ['REPO']}/code-scanning/analyses?per_page=100",
                                     headers={"Authorization": f"Bearer {os.environ['GH_TOKEN']}",
                                              "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            cats = {a.get("category", "") for a in json.load(resp) if a.get("commit_sha") == os.environ["SHA"]}
        if want <= cats:
            break
        time.sleep(10)
    missing = sorted(want - cats)
    if missing:
        err(f"code-scanning categories missing for this commit: {missing}")
    print(f"::notice title=code scanning::{len(want & cats)}/{len(want)} expected categories present")

print(f"::notice title=adoption {mode}::{'PASS' if not errors else 'FAIL'} ({len(errors)} problem(s))")
sys.exit(1 if errors else 0)
