"""Detonator: fork-and-bait differential detonation for the AI software supply chain."""
from .pipeline import detonate_package, Detonation
from .runner import LocalRunner, DaytonaRunner, Runner
from .baits import DEFAULT_BAITS, MVP_BAITS
from .analyze import Verdict

__all__ = ["detonate_package", "Detonation", "LocalRunner", "DaytonaRunner",
           "Runner", "DEFAULT_BAITS", "MVP_BAITS", "Verdict"]
