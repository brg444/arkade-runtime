#!/usr/bin/env python3
"""Operate only the isolated rolling-allowance regtest node."""
import base64
import json
import sys
import time
import urllib.request

URL = "http://127.0.0.1:25443"
AUTH = base64.b64encode(b"admin1:123").decode()


def rpc(method, params=None, wallet=False):
    endpoint = URL + ("/wallet/rolling-regtest" if wallet else "")
    body = json.dumps({"jsonrpc": "2.0", "id": "rolling-regtest", "method": method, "params": params or []}).encode()
    req = urllib.request.Request(endpoint, data=body, headers={"Authorization": "Basic " + AUTH, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as response:
        result = json.load(response)
    if result.get("error"):
        raise RuntimeError(result["error"])
    return result["result"]


def initialize():
    if rpc("getblockchaininfo")["chain"] != "regtest":
        raise RuntimeError("Refusing a non-regtest node")
    if "rolling-regtest" not in rpc("listwallets"):
        known = {entry["name"] for entry in rpc("listwalletdir")["wallets"]}
        rpc("loadwallet" if "rolling-regtest" in known else "createwallet", ["rolling-regtest"])
    address = rpc("getnewaddress", wallet=True)
    height = rpc("getblockcount")
    if height < 110:
        rpc("generatetoaddress", [110 - height, address])
    return address


if __name__ == "__main__":
    address = initialize()
    command = sys.argv[1] if len(sys.argv) > 1 else "init"
    if command == "mine":
        while True:
            rpc("generatetoaddress", [1, address])
            time.sleep(5)
    elif command == "fund":
        txid = rpc("sendtoaddress", [sys.argv[2], float(sys.argv[3])], wallet=True)
        rpc("generatetoaddress", [1, address])
        print(txid)
    elif command == "init":
        print(json.dumps({"chain": "regtest", "height": rpc("getblockcount")}))
    else:
        raise RuntimeError("Expected init, mine, or fund")
