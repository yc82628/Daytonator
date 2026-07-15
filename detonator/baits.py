"""Bait definitions for fork-and-bait differential detonation.

Each Bait describes one *baited environment* that a package is detonated in.
We snapshot a clean sandbox once, then fork it into one sandbox per bait.
A behaviour that appears ONLY in a baited fork is provably triggered by that
bait -- that differential is what catches malware which hides from a plain run.

A bait is just:
  - env_vars:   environment variables present in that fork
  - files:      files planted into the fork's home dir (path -> contents)
  - clock_skew_days: optionally jump the system clock forward (trips time-bombs)

All planted secrets are FAKE canary values. Their only purpose is to see whether
an untrusted package reaches for them. Nothing here is a real credential.
"""
from __future__ import annotations
from dataclasses import dataclass, field


# Unique tokens we plant. If any of these strings leaves the sandbox (e.g. in an
# outbound request body), that is unambiguous proof of exfiltration.
CANARY_SSH = "CANARY-ssh-7f3a91d2-DO-NOT-TRUST-this-is-a-decoy-key"
CANARY_AWS_KEY = "AKIA_CANARY_EXAMPLE_4242"
CANARY_AWS_SECRET = "canary/secret/EXAMPLEdoNotUse+4242deadbeef"


@dataclass(frozen=True)
class Bait:
    name: str
    description: str
    env_vars: dict[str, str] = field(default_factory=dict)
    files: dict[str, str] = field(default_factory=dict)   # relative-to-home path -> contents
    clock_skew_days: int = 0

    # Every canary value this bait plants, so the analyzer can scan traces/egress
    # for them and attribute a leak to the right trigger.
    @property
    def canaries(self) -> list[str]:
        out = list(self.env_vars.values())
        for contents in self.files.values():
            out.append(contents)
        return [c for c in out if "CANARY" in c or "canary" in c]


CONTROL = Bait(
    name="control",
    description="Clean environment, no bait. The baseline every fork is compared against.",
)

SSH_BAIT = Bait(
    name="ssh",
    description="A planted private SSH key. Catches packages that scrape ~/.ssh.",
    files={".ssh/id_rsa": (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        f"{CANARY_SSH}\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )},
)

AWS_BAIT = Bait(
    name="aws",
    description="Fake cloud credentials in env + ~/.aws. Catches credential stealers.",
    env_vars={
        "AWS_ACCESS_KEY_ID": CANARY_AWS_KEY,
        "AWS_SECRET_ACCESS_KEY": CANARY_AWS_SECRET,
    },
    files={".aws/credentials": (
        "[default]\n"
        f"aws_access_key_id = {CANARY_AWS_KEY}\n"
        f"aws_secret_access_key = {CANARY_AWS_SECRET}\n"
    )},
)

PROD_BAIT = Bait(
    name="prod",
    description="Looks like a production host. Catches malware that only fires in 'real' envs.",
    env_vars={
        "NODE_ENV": "production",
        "ENVIRONMENT": "production",
        "HOSTNAME": "prod-web-01.internal",
    },
)

CLOCK_BAIT = Bait(
    name="clock",
    description="System clock jumped 400 days forward. Trips time-delayed logic bombs.",
    clock_skew_days=400,
)


# The default fork set. Start with CONTROL + AWS for the MVP (that pair alone is a
# complete demo); add the rest as you go.
DEFAULT_BAITS: list[Bait] = [CONTROL, SSH_BAIT, AWS_BAIT, PROD_BAIT, CLOCK_BAIT]
MVP_BAITS: list[Bait] = [CONTROL, AWS_BAIT]
