"""Command-line entrypoint.

Examples
--------
# offline, against a local demo package:
python -m detonator.cli --local demo_packages/evasive_stealer \\
    --import-name evasive_stealer --backend local --full

# on Daytona, against a real PyPI package:
python -m detonator.cli requests --backend daytona
"""
from __future__ import annotations
try:
    from dotenv import load_dotenv; load_dotenv()
except Exception:
    pass
import argparse, json, sys

from .baits import DEFAULT_BAITS, MVP_BAITS
from .runner import LocalRunner, DaytonaRunner
from .pipeline import detonate_package

_COLOR = {"safe": "\033[92m", "suspicious": "\033[93m", "malicious": "\033[91m"}
_RESET = "\033[0m"

# Built-in demo packages -> (local folder, import name). Lets you run e.g.
# `detonator.cli evasive-stealer --backend daytona` and have it upload the local
# folder into the sandbox instead of looking for it on PyPI.
DEMOS = {
    "benign-demo": ("demo_packages/benign_demo", "benign_demo"),
    "canary-stealer": ("demo_packages/canary_stealer", "canary_stealer"),
    "evasive-stealer": ("demo_packages/evasive_stealer", "evasive_stealer"),
}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="detonator")
    ap.add_argument("package", nargs="?", help="PyPI package name to detonate")
    ap.add_argument("--local", dest="local_path", help="path to a local package dir")
    ap.add_argument("--import-name", help="module name to import (if != package name)")
    ap.add_argument("--backend", choices=["local", "daytona"], default="local")
    ap.add_argument("--full", action="store_true", help="use all baits (default: MVP set)")
    ap.add_argument("--json", action="store_true", help="emit JSON only")
    args = ap.parse_args(argv)

    package = args.package or (args.local_path.rstrip("/").split("/")[-1] if args.local_path else None)
    if not package:
        ap.error("provide a package name or --local PATH")

    # if the package is a known demo name, auto-use its local folder
    local_path = args.local_path
    import_name = args.import_name
    if not local_path and package in DEMOS:
        local_path, demo_import = DEMOS[package]
        import_name = import_name or demo_import

    runner = DaytonaRunner() if args.backend == "daytona" else LocalRunner()
    runner.prepare()
    baits = DEFAULT_BAITS if args.full else MVP_BAITS
    det = detonate_package(runner, package, baits=baits,
                           import_name=import_name, local_path=local_path)
    runner.cleanup()

    if args.json:
        print(json.dumps(det.to_dict(), indent=2))
        return 0

    v = det.verdict
    c = _COLOR.get(v.label, "")
    print(f"\n  package   {det.package}")
    print(f"  verdict   {c}{v.label.upper()}{_RESET}  ({v.score}/100, via {v.via})")
    print(f"  triggers  {', '.join(v.triggered_by) or 'none'}")
    print(f"\n  {v.explanation}\n")
    if v.evidence:
        print("  behaviour seen only under bait:")
        for e in v.evidence:
            print(f"    - {e}")
    print()
    return 0 if v.label == "safe" else 2


if __name__ == "__main__":
    sys.exit(main())
