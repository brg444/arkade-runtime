#!/usr/bin/env python3
"""Initialize only the dedicated loopback regtest wallet and fund its batches."""
import json
import subprocess
import urllib.request
from pathlib import Path

BASE = "http://127.0.0.1:26060"
PASSWORD = "rolling-regtest-only"


def request(path, body=None):
    raw = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, raw, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as response:
        return json.load(response)


if request("/v1/wallet/network").get("network") != "regtest":
    raise SystemExit("refusing non-regtest wallet")
status = request("/v1/wallet/status")
if not status.get("initialized"):
    seed = request("/v1/wallet/seed")["seed"]
    request("/v1/wallet/create", {"seed": seed, "password": PASSWORD})
    del seed
if not status.get("unlocked"):
    request("/v1/wallet/unlock", {"password": PASSWORD})
print("Dedicated regtest wallet unlocked")
