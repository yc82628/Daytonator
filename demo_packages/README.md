# Demo packages — TEST FIXTURES, NOT MALWARE

Three local packages used to prove the detector. All secrets are fake canaries and
all "exfiltration" targets are unroutable RFC-5737 documentation IPs (203.0.113.x).
They reach nothing and steal nothing real.

- benign_demo      — harmless. Expected verdict: safe.
- canary_stealer   — reads canaries + connects out on EVERY run. Expected: malicious (unconditional).
- evasive_stealer  — THE DEMO STAR. Silent on a clean run; fires only when it sees the
                     planted AWS creds (i.e. only in the AWS fork). Expected: malicious (evasive).
                     This is what makes fork-and-bait visible on stage.
