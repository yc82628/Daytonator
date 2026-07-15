# DayTonator

**Fork-and-bait differential detonation for the AI software supply chain.**

AI coding agents hallucinate package names; attackers register those names with malware
(slopsquatting). DayTonator detonates a suspicious package inside isolated **Daytona**
sandboxes, **forks one snapshot into several baited environments**, and lets a model judge
what the package does across the forks. Malware that hides on a clean run reveals itself in
the fork that baits it.

Built on **Daytona** (sandbox forking), **Featherless** (the model that writes the verdict),
and **Lovable** (the console UI).

---

## How it works

1. **Snapshot** one clean Daytona sandbox — a single, identical starting point.
2. **Fork** it into several environments, each with one planted *bait*: control (nothing),
   AWS creds, an SSH key, a production-looking env.
3. **Detonate** the package in every fork while `strace` records file, network, and process
   activity.
4. **Differential** — behaviour that appears in a baited fork but not in control was provably
   triggered by that bait. Evasive malware can't hide.
5. **A model explains** the verdict (safe / suspicious / malicious) in plain English.

---

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # fill in your keys (see below)
```

`.env`:
```
DAYTONA_API_KEY=...             # from app.daytona.io
DAYTONA_TARGET=eu
BACKEND=daytona                 # or "local" to run offline without Daytona
FEATHERLESS_API_KEY=...         # free open-source models; falls back to a heuristic if unset
FEATHERLESS_MODEL=Qwen/Qwen2.5-72B-Instruct
```

### Run from the command line
```bash
python -m detonator.cli evasive-stealer --backend daytona --full
# -> MALICIOUS (95/100, via featherless), triggered by the AWS fork
```

### Run the web console
```bash
uvicorn server:app --reload --port 8000   # open http://localhost:8000
```

### Run offline (no Daytona, no keys)
```bash
python tests/smoke_test.py    # all three demo packages classify correctly
```
Offline uses a local strace runner and a transparent heuristic verdict, so the whole pipeline
works with zero credentials for development.

---

## Architecture

```
detonator/
  baits.py      bait environments (control / ssh / aws / prod / clock) + fake canaries
  trace.py      Trace model + strace parser
  harness.py    in-sandbox provocation + strace command
  runner.py     LocalRunner (offline) and DaytonaRunner (snapshot + fork)
  analyze.py    cross-fork differential + model verdict (Featherless/Anthropic) + heuristic fallback
  pipeline.py   package -> fork across baits -> capture -> verdict
  cli.py        command-line entrypoint
server.py       FastAPI backend + web console (/api/detonate)
web/index.html  built-in console (a Lovable UI can also call /api/detonate)
demo_packages/  benign / canary_stealer / evasive_stealer (safe test fixtures)
tests/          smoke_test.py + sample_output_evasive.json (the UI data contract)
```

**LLM backends:** the verdict tries Featherless first, then Anthropic, then a built-in
heuristic — so it never fails, and the explanation is model-written when a key is present.

---

## Safety note

The demo packages are **test fixtures, not malware**. They read only fake planted canary
values and "exfiltrate" to unroutable RFC-5737 documentation IPs (203.0.113.x). They reach
nothing and steal nothing real; their only purpose is to make the detector fire on demand.

## Roadmap

microVM-grade isolation for genuinely hostile code (today's sandboxes share a kernel, so this
is behavioural early warning, not bulletproof containment); more baits; an agentic mode where
the model writes custom provocations and re-forks until confident; and a registry-middleware
mode that gates an agent's `pip install` in real time.