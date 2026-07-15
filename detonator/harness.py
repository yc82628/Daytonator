"""Builds the code that provokes a package and the command that traces it.

`exercise_for` is the fallback, static provocation: install the package, import
it, and poke its public surface so install-time AND import-time behaviour fire.

The AI upgrade (see analyze.generate_exercise) replaces this with a harness the
model writes after reading the package source -- that's what makes Detonator an
agent rather than a scanner. Keep this deterministic version as the floor.
"""
from __future__ import annotations

STRACE_SYSCALLS = "network,connect,open,openat,execve,unlink,chmod"


def exercise_for(import_name: str) -> str:
    """A generic Python provocation script for a package.

    `import_name` is what you'd type after `import` (often, but not always, the
    distribution name). We import it, then call any zero-arg public callables to
    coax lazy/conditional code paths into running.
    """
    return f'''
import importlib, traceback
TARGET = {import_name!r}
try:
    mod = importlib.import_module(TARGET)
    print("[harness] imported", TARGET)
    for attr in dir(mod):
        if attr.startswith("_"):
            continue
        obj = getattr(mod, attr, None)
        if callable(obj):
            try:
                obj()              # poke zero-arg callables
            except Exception:
                pass
except Exception:
    traceback.print_exc()
print("[harness] done")
'''


def strace_command(exercise_path: str, trace_path: str, python_bin: str = "python3") -> str:
    """The shell command that runs the exercise under strace, writing the raw
    syscall log to `trace_path`. -f follows child processes (so a spawned shell
    is still captured); -qq quiets attach/exit noise; -s 200 keeps string args
    long enough to see URLs and paths."""
    return (
        f"strace -f -qq -s 200 -e trace={STRACE_SYSCALLS} "
        f"-o {trace_path} {python_bin} {exercise_path}"
    )
