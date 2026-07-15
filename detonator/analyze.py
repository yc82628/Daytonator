"""The brain: turn per-fork traces into a verdict + plain-English explanation.

Two AI touchpoints (the reason this is an AI application, not a scanner):
  generate_exercise() -- the model reads the package and writes a provocation
                         harness tailored to it. Optional; falls back to generic.
  verdict()           -- the model reasons over the cross-fork DIFFERENTIAL and
                         explains intent. Falls back to a transparent heuristic so
                         the pipeline still runs with no API key (for offline dev).

The differential is the signal: behaviour present in a baited fork but absent in
control is, by construction, triggered by that bait.
"""
from __future__ import annotations
import os, json
from dataclasses import dataclass

from .trace import Trace


@dataclass
class Verdict:
    package: str
    label: str          # "safe" | "suspicious" | "malicious"
    score: int          # 0-100
    explanation: str
    triggered_by: list[str]      # which baits provoked behaviour
    evidence: list[str]          # human-readable behaviour lines
    via: str            # "ai" | "heuristic"

    def to_dict(self) -> dict:
        return self.__dict__


def differential(traces: list[Trace]) -> dict:
    """Behaviour in each baited fork minus behaviour in control."""
    control = next((t for t in traces if t.bait == "control"), None)
    base = control.fingerprint() if control else set()
    out = {}
    for t in traces:
        if t.bait == "control":
            continue
        only_here = t.fingerprint() - base
        out[t.bait] = sorted(only_here)
    return out


# --------------------------------------------------------------------------- #
# AI provocation: model writes a harness for this specific package             #
# --------------------------------------------------------------------------- #
def generate_exercise(package: str, source_excerpt: str, model: str | None = None) -> str | None:
    prompt = (
        "You are a malware analyst. Write a short Python script that imports and "
        f"exercises the package `{package}` to surface any install/import-time or "
        "lazily-triggered behaviour. Call its public entry points with benign "
        "arguments. Output ONLY runnable Python, no markdown, no commentary.\n\n"
        f"Package source excerpt:\n{source_excerpt[:6000]}"
    )
    text, _ = _llm_chat(prompt, max_tokens=1024)
    if not text:
        return None
    return text.replace("```python", "").replace("```", "").strip() or None


# --------------------------------------------------------------------------- #
# Verdict                                                                      #
# --------------------------------------------------------------------------- #
def verdict(package: str, traces: list[Trace], model: str = "claude-opus-4-8") -> Verdict:
    diff = differential(traces)
    triggered = [bait for bait, evs in diff.items() if evs]
    evidence = sorted({e for evs in diff.values() for e in evs})

    if _llm_available():
        v = _ai_verdict(package, traces, diff)
        if v is not None:
            return v
    return _heuristic_verdict(package, traces, diff, triggered, evidence)


def _fork_kinds(trace: Trace) -> set[str]:
    return {e.kind for e in trace.events}


def _heuristic_verdict(package, traces, diff, triggered, evidence) -> Verdict:
    """Transparent fallback so the pipeline works with no API key.

    Looks at two things:
      absolute  -- does ANY fork (incl. control) show credential theft? -> malicious
      evasion   -- does the theft appear only under bait, not on the clean run?
    """
    control = next((t for t in traces if t.bait == "control"), None)
    control_theft = bool(control and "secret_read" in _fork_kinds(control)
                         and ({"network", "exfil"} & _fork_kinds(control)))

    theft_forks = [t.bait for t in traces
                   if "secret_read" in _fork_kinds(t) and ({"network", "exfil"} & _fork_kinds(t))]
    any_theft = bool(theft_forks)
    any_signal_kinds = {k for t in traces for k in _fork_kinds(t)
                        if k in ("secret_read", "network", "process", "exfil")}

    # absolute evidence from every fork (normalized), plus the evasion differential
    abs_evidence = sorted({f"{e.kind}:{e.detail}" for t in traces for e in t.events})

    if any_theft:
        evasive = not control_theft and any(b != "control" for b in theft_forks)
        score = 95 if evasive else 85
        label = "malicious"
        if evasive:
            why = (f"Reads planted secrets and opens a network connection in the "
                   f"{', '.join(b for b in theft_forks if b!='control')} fork(s) while "
                   "staying silent on the clean run. Credential theft that hides from "
                   "a normal sandbox.")
        else:
            why = ("Reads planted secrets and opens a network connection on every run. "
                   "This is unconditional credential theft.")
        return Verdict(package, label, score, why, triggered or theft_forks,
                       abs_evidence, via="heuristic")

    if any_signal_kinds:
        return Verdict(package, "suspicious", 55,
                       "Shows behaviour a normal library would not ("
                       + ", ".join(sorted(any_signal_kinds)) + "), though not a full "
                       "theft chain.", triggered, abs_evidence, via="heuristic")

    return Verdict(package, "safe", 6,
                   "No sensitive or network behaviour observed across forks.",
                   [], [], via="heuristic")


def _ai_verdict(package, traces, diff) -> Verdict | None:
    payload = {
        "package": package,
        "control_behaviour": sorted(next((t.fingerprint() for t in traces
                                          if t.bait == "control"), set())),
        "differential_by_bait": diff,
    }
    prompt = (
        "You are a supply-chain malware analyst. Below is the behaviour of a "
        "package detonated across several baited sandbox forks. The 'control' "
        "fork had no bait. Each other fork added one bait (planted ssh key, fake "
        "AWS creds, a production-looking env, or a skewed clock). Behaviour listed "
        "under a bait appeared ONLY in that fork, so the bait triggered it.\n\n"
        "Decide if the package is safe, suspicious, or malicious, and explain the "
        "INTENT in two or three plain sentences a developer would understand. "
        "Reading planted secrets and then opening network connections is credential "
        "theft. Behaviour that fires only under a bait and hides on the clean run is "
        "evasion and raises severity.\n\n"
        "Respond ONLY as JSON: {\"label\": ..., \"score\": 0-100, "
        "\"explanation\": ...}.\n\n"
        f"{json.dumps(payload, indent=2)}"
    )
    text, provider = _llm_chat(prompt, max_tokens=900)
    if not text:
        return None
    data = _extract_json(text)
    if not data:
        return None
    try:
        triggered = [b for b, e in diff.items() if e]
        evidence = sorted({e for evs in diff.values() for e in evs})
        return Verdict(package, str(data["label"]).lower(), int(data["score"]),
                       data["explanation"], triggered, evidence, via=provider)
    except Exception:
        return None


def _extract_json(text: str):
    """Pull the first valid JSON object out of an LLM reply, tolerating reasoning
    blocks (<think>...</think>), code fences, and prose around it."""
    import re
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.S)
    text = text.replace("```json", "").replace("```", "")
    for s in (i for i, ch in enumerate(text) if ch == "{"):
        depth = 0
        for i in range(s, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[s:i + 1])
                    except Exception:
                        break
    return None


def _llm_available() -> bool:
    return bool(os.environ.get("FEATHERLESS_API_KEY") or os.environ.get("ANTHROPIC_API_KEY"))


def _llm_chat(prompt: str, max_tokens: int = 600) -> tuple[str | None, str | None]:
    """Unified chat call. Tries Featherless (free open-source models, OpenAI-
    compatible) first, then Anthropic. Returns (text, provider_name)."""
    fk = os.environ.get("FEATHERLESS_API_KEY")
    if fk:
        try:
            from openai import OpenAI
            client = OpenAI(base_url="https://api.featherless.ai/v1", api_key=fk)
            model = os.environ.get("FEATHERLESS_MODEL", "Qwen/Qwen2.5-7B-Instruct")
            r = client.chat.completions.create(
                model=model, max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}])
            return r.choices[0].message.content, "featherless"
        except Exception as e:
            if os.environ.get("DETONATOR_DEBUG"):
                import sys; print(f"[featherless error] {e}", file=sys.stderr)
    ak = os.environ.get("ANTHROPIC_API_KEY")
    if ak:
        try:
            import anthropic
            client = anthropic.Anthropic()
            model = os.environ.get("ANTHROPIC_MODEL", "claude-opus-4-8")
            msg = client.messages.create(
                model=model, max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}])
            return "".join(b.text for b in msg.content
                           if getattr(b, "type", "") == "text"), "anthropic"
        except Exception as e:
            if os.environ.get("DETONATOR_DEBUG"):
                import sys; print(f"[anthropic error] {e}", file=sys.stderr)
    return None, None
