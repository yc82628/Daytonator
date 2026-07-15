"""Structured behaviour traces and a parser for raw strace output.

A Trace is the normalized record of what a package did inside one fork:
which sensitive files it opened, which network connections it attempted, and
which child processes (shells, curl, etc.) it spawned. The analyzer diffs these
across forks.
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field, asdict


# Paths that should never be touched by a freshly-installed library.
SENSITIVE_PATH_HINTS = (".ssh", ".aws", ".npmrc", ".netrc", "id_rsa",
                        "credentials", "/etc/passwd", "/etc/shadow", ".env",
                        ".docker/config", ".kube/config", ".git-credentials")

# Programs whose execution from inside an import is a strong red flag.
SUSPICIOUS_BINARIES = ("sh", "bash", "zsh", "curl", "wget", "nc", "ncat",
                        "python", "node", "powershell", "base64", "chmod")


@dataclass
class TraceEvent:
    kind: str        # "network" | "secret_read" | "process" | "file_write"
    detail: str      # human-readable line, e.g. "connect 203.0.113.5:443"
    raw: str = ""    # the originating strace line, for evidence


@dataclass
class Trace:
    bait: str
    package: str
    events: list[TraceEvent] = field(default_factory=list)
    exit_code: int | None = None
    stdout: str = ""
    error: str = ""

    def add(self, kind: str, detail: str, raw: str = "") -> None:
        self.events.append(TraceEvent(kind=kind, detail=detail, raw=raw))

    def of_kind(self, kind: str) -> list[TraceEvent]:
        return [e for e in self.events if e.kind == kind]

    def fingerprint(self) -> set[str]:
        """A set of (kind:detail) strings, used to diff forks against each other."""
        return {f"{e.kind}:{e.detail}" for e in self.events}

    def to_dict(self) -> dict:
        return {
            "bait": self.bait,
            "package": self.package,
            "exit_code": self.exit_code,
            "events": [asdict(e) for e in self.events],
            "error": self.error,
        }


_CONNECT_RE = re.compile(r'connect\((?:\d+,\s*)?\{sa_family=AF_INET6?,\s*'
                        r'sin6?_port=htons\((\d+)\),\s*(?:sin6?_addr|inet_pton[^,]*)'
                        r'[^"]*"([0-9a-fA-F:.]+)"')
_OPEN_RE = re.compile(r'open(?:at)?\([^,]*,?\s*"([^"]+)"')
_EXEC_RE = re.compile(r'execve\("([^"]+)"')


def parse_strace(raw_output: str, bait: str, package: str) -> Trace:
    """Turn raw strace stderr into a structured Trace.

    Tolerant by design: strace formatting varies across versions, so we match
    loosely and prefer false-structure over crashing. The analyzer is the final
    judge; this just surfaces candidate events.
    """
    trace = Trace(bait=bait, package=package)
    for line in raw_output.splitlines():
        # network connects to a real (non-loopback) address
        m = _CONNECT_RE.search(line)
        if m:
            port, addr = m.group(1), m.group(2)
            if not _is_local(addr):
                trace.add("network", f"connect {addr}:{port}", line.strip())
            continue
        # sensitive file opens
        m = _OPEN_RE.search(line)
        if m:
            path = m.group(1)
            if any(h in path for h in SENSITIVE_PATH_HINTS):
                trace.add("secret_read", f"open {_norm_path(path)}", line.strip())
            continue
        # suspicious child processes
        m = _EXEC_RE.search(line)
        if m:
            binpath = m.group(1)
            base = binpath.rsplit("/", 1)[-1]
            # ignore the python we launched ourselves; flag re-exec of shells etc.
            if base in SUSPICIOUS_BINARIES and base != "python3":
                trace.add("process", f"exec {binpath}", line.strip())
    return trace


def _norm_path(path: str) -> str:
    """Strip per-fork temp/home prefixes so the same secret reads the same way in
    every fork (essential for the cross-fork differential to cancel correctly)."""
    if "/home/" in path:
        return path.split("/home/", 1)[1].lstrip("/")
    if "/home" == path[:5] and path.count("/") > 2:
        return path.split("/", 3)[-1]
    return path


def _is_local(addr: str) -> bool:
    return (addr.startswith("127.") or addr in ("::1", "0.0.0.0", "::")
            or addr.startswith("10.") or addr.startswith("192.168.")
            or addr.startswith("169.254."))
