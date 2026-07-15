"""Offline smoke test: confirms the three demo packages classify correctly.
Run: python tests/smoke_test.py   (no API key or Daytona needed)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detonator import LocalRunner, detonate_package, DEFAULT_BAITS

CASES = {"benign_demo": "safe", "canary_stealer": "malicious", "evasive_stealer": "malicious"}
runner = LocalRunner(); runner.prepare()
ok = True
for pkg, expect in CASES.items():
    det = detonate_package(runner, pkg, baits=DEFAULT_BAITS,
                           import_name=pkg, local_path=f"demo_packages/{pkg}")
    got = det.verdict.label
    mark = "PASS" if got == expect else "FAIL"
    if got != expect: ok = False
    print(f"  [{mark}] {pkg:18s} expected {expect:10s} got {got} ({det.verdict.score})")
print("\nALL PASS" if ok else "\nFAILURES"); sys.exit(0 if ok else 1)
