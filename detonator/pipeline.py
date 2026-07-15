"""End-to-end orchestration: package -> fork across baits -> capture -> verdict."""
from __future__ import annotations
from dataclasses import dataclass

from .baits import Bait, MVP_BAITS
from .runner import Runner
from .trace import Trace
from . import analyze


@dataclass
class Detonation:
    package: str
    verdict: "analyze.Verdict"
    traces: list[Trace]

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "verdict": self.verdict.to_dict(),
            "traces": [t.to_dict() for t in self.traces],
        }


def detonate_package(runner: Runner, package: str, *, baits: list[Bait] | None = None,
                     import_name: str | None = None, local_path: str | None = None,
                     exercise: str | None = None) -> Detonation:
    """Fork `package` across every bait, capture each, and judge the differential."""
    baits = baits or MVP_BAITS
    traces: list[Trace] = []
    for bait in baits:
        trace = runner.detonate(package, bait, import_name=import_name,
                                exercise=exercise, local_path=local_path)
        traces.append(trace)
    v = analyze.verdict(package, traces)
    return Detonation(package=package, verdict=v, traces=traces)
