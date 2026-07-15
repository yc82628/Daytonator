"""Detonation backends.

Two implementations behind one interface:

  LocalRunner   -- runs everything on this machine using a throwaway HOME dir and
                   strace. No Daytona, no network account. Use it tonight to build
                   and test the analyzer + UI offline, and as a live fallback if
                   Daytona fights you on the day. NOT isolation -- dev only.

  DaytonaRunner -- the real thing. Snapshot a clean sandbox once, then fork it
                   into one sandbox per bait via create-from-snapshot. This is the
                   fork-and-bait mechanic and the part judges care about.

Both return a Trace per (package, bait).
"""
from __future__ import annotations
import os, subprocess, tempfile, shutil, textwrap, uuid, io, tarfile
from abc import ABC, abstractmethod

from .baits import Bait
from .harness import exercise_for, strace_command
from .trace import Trace, parse_strace


class Runner(ABC):
    @abstractmethod
    def prepare(self) -> None: ...
    @abstractmethod
    def detonate(self, package: str, bait: Bait, *, import_name: str | None = None,
                 exercise: str | None = None, local_path: str | None = None) -> Trace: ...
    def cleanup(self) -> None:  # optional
        pass


# --------------------------------------------------------------------------- #
# Local backend                                                               #
# --------------------------------------------------------------------------- #
class LocalRunner(Runner):
    """Detonate on the host in a throwaway HOME. Dev/test/fallback only."""

    def prepare(self) -> None:
        if shutil.which("strace") is None:
            raise RuntimeError("strace not found. `apt-get install -y strace`.")

    def detonate(self, package, bait, *, import_name=None, exercise=None, local_path=None):
        import_name = import_name or package.replace("-", "_")
        work = tempfile.mkdtemp(prefix=f"deto_{bait.name}_")
        home = os.path.join(work, "home")
        os.makedirs(home, exist_ok=True)
        target = os.path.join(work, "site")   # where the package is installed
        os.makedirs(target, exist_ok=True)
        try:
            # 1. install the package into an isolated target dir
            install = self._install(package, local_path, target)

            # 2. plant the bait's files into the throwaway HOME
            for rel, contents in bait.files.items():
                p = os.path.join(home, rel)
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w") as f:
                    f.write(contents)

            # 3. write the exercise script (AI-generated if provided, else generic)
            ex_path = os.path.join(work, "exercise.py")
            body = exercise or exercise_for(import_name)
            with open(ex_path, "w") as f:
                f.write(f"import sys; sys.path.insert(0, {target!r})\n" + body)

            # 4. run it under strace with the bait environment
            trace_path = os.path.join(work, "trace.txt")
            env = dict(os.environ, HOME=home, **bait.env_vars)
            cmd = strace_command(ex_path, trace_path)
            proc = subprocess.run(cmd, shell=True, env=env, cwd=work,
                                  capture_output=True, text=True, timeout=120)

            raw = ""
            if os.path.exists(trace_path):
                with open(trace_path, errors="ignore") as f:
                    raw = f.read()
            trace = parse_strace(raw, bait=bait.name, package=package)
            trace.exit_code = proc.returncode
            trace.stdout = (install + "\n" + proc.stdout)[-4000:]
            if proc.returncode != 0 and not trace.events:
                trace.error = proc.stderr[-1000:]

            # cross-check: did any planted canary value appear in stdout/trace?
            self._scan_canaries(trace, bait, raw + proc.stdout)
            return trace
        finally:
            shutil.rmtree(work, ignore_errors=True)

    @staticmethod
    def _install(package, local_path, target) -> str:
        src = local_path or package
        try:
            r = subprocess.run(
                ["pip", "install", "--no-deps", "--quiet", "--target", target, src],
                capture_output=True, text=True, timeout=120)
            return (r.stdout + r.stderr)[-1000:]
        except Exception as e:
            return f"[install error] {e}"

    @staticmethod
    def _scan_canaries(trace: Trace, bait: Bait, blob: str) -> None:
        for canary in bait.canaries:
            tok = canary.split("\n")[0][:24]
            if tok and tok in blob and "network" in {e.kind for e in trace.events}:
                trace.add("exfil", f"canary value left the process ({bait.name})")


# --------------------------------------------------------------------------- #
# Daytona backend                                                             #
# --------------------------------------------------------------------------- #
class DaytonaRunner(Runner):
    """Real fork-and-bait on Daytona.

    Verified against the current daytona SDK docs:
      Daytona() reads DAYTONA_API_KEY (+ optional DAYTONA_TARGET region).
      daytona.snapshot.create(CreateSnapshotParams(name=, image=Image...))
      daytona.create(CreateSandboxFromSnapshotParams(snapshot=, env_vars=, language="python"))
      sandbox.get_user_home_dir(); sandbox.fs.upload_file(bytes, path) / download_file(path)
      sandbox.process.exec(cmd, env=, timeout=); sandbox.delete()
    """

    def __init__(self, snapshot_name: str | None = None):
        Daytona, *_ = _imports()
        self.daytona = Daytona()                       # reads DAYTONA_API_KEY / DAYTONA_TARGET
        self.snapshot_name = snapshot_name or f"detonator-base-{uuid.uuid4().hex[:8]}"
        self._snapshot = None

    def prepare(self) -> None:
        _, Image, CreateSnapshotParams, _, _ = _imports()
        # Base image: python + strace. Snapshot it ONCE; every bait fork is created
        # from this exact frozen state (that's the "fork from one snapshot" mechanic).
        image = (Image.debian_slim("3.12")
                 .run_commands("apt-get update && apt-get install -y strace"))
        self._snapshot = self.daytona.snapshot.create(
            CreateSnapshotParams(name=self.snapshot_name, image=image),
            on_logs=lambda c: None,
        )

    def detonate(self, package, bait, *, import_name=None, exercise=None, local_path=None):
        _, _, _, CreateSandboxFromSnapshotParams, _ = _imports()
        import_name = import_name or package.replace("-", "_")
        # FORK: a fresh sandbox from the frozen snapshot, carrying this bait's env.
        sandbox = self.daytona.create(CreateSandboxFromSnapshotParams(
            snapshot=self.snapshot_name,
            env_vars=dict(bait.env_vars),
            language="python",
        ))
        try:
            home = (sandbox.get_user_home_dir() or "/home/daytona").rstrip("/")
            env = dict(bait.env_vars, HOME=home)

            # plant bait files (make parent dirs first)
            for rel, contents in bait.files.items():
                parent = "/".join(f"{home}/{rel}".split("/")[:-1])
                sandbox.process.exec(f"mkdir -p {parent}")
                sandbox.fs.upload_file(contents.encode(), f"{home}/{rel}")

            # get the package into the sandbox: either a local folder (upload +
            # extract onto sys.path) or a real PyPI name (pip install).
            prefix = "import sys\n"
            if local_path:
                sandbox.fs.upload_file(_tar_dir(local_path), f"{home}/pkg.tar.gz")
                sandbox.process.exec(
                    f"mkdir -p {home}/pkgsrc && tar -xzf {home}/pkg.tar.gz -C {home}/pkgsrc",
                    timeout=60)
                prefix += f"sys.path.insert(0, {home + '/pkgsrc'!r})\n"
            else:
                sandbox.process.exec(
                    f"pip install --no-deps --break-system-packages {package}", timeout=120)

            # write + run the exercise under strace
            body = exercise or exercise_for(import_name)
            sandbox.fs.upload_file((prefix + body).encode(), f"{home}/exercise.py")
            cmd = strace_command(f"{home}/exercise.py", f"{home}/trace.txt")
            res = sandbox.process.exec(cmd, env=env, timeout=150)

            raw = ""
            try:
                raw = sandbox.fs.download_file(f"{home}/trace.txt").decode(errors="ignore")
            except Exception:
                pass
            trace = parse_strace(raw, bait=bait.name, package=package)
            trace.exit_code = getattr(res, "exit_code", None)
            trace.stdout = (getattr(res, "result", "") or "")[-4000:]
            return trace
        finally:
            try:
                sandbox.delete()
            except Exception:
                pass

    def cleanup(self) -> None:
        try:
            if self._snapshot:
                self.daytona.snapshot.delete(self._snapshot)
        except Exception:
            pass


def _imports():
    """Import the Daytona SDK, tolerating both the `daytona` and `daytona_sdk`
    package names (Daytona renamed it; either may be installed)."""
    try:
        from daytona_sdk import (Daytona, Image, CreateSnapshotParams,
                                 CreateSandboxFromSnapshotParams, DaytonaConfig)
    except ImportError:
        from daytona import (Daytona, Image, CreateSnapshotParams,
                             CreateSandboxFromSnapshotParams, DaytonaConfig)
    return Daytona, Image, CreateSnapshotParams, CreateSandboxFromSnapshotParams, DaytonaConfig


def _tar_dir(path: str) -> bytes:
    """Package a local directory into tar.gz bytes for upload to a sandbox.
    The package's contents land at the tar root, so extracting puts e.g.
    pyproject.toml and the module dir directly under the extraction folder."""
    skip = ("__pycache__", ".egg-info", "build", ".git", ".venv")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if not any(s in d for s in skip)]
            for fn in files:
                if fn.endswith((".pyc",)):
                    continue
                full = os.path.join(root, fn)
                arc = os.path.relpath(full, path)
                tar.add(full, arcname=arc)
    return buf.getvalue()
