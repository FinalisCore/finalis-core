#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

import argparse
import json
import sys
import time
import urllib.request


def rpc(url: str, method: str, params: dict) -> dict:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        obj = json.loads(resp.read().decode("utf-8"))
    if "error" in obj:
        raise RuntimeError(str(obj["error"]))
    return obj["result"]


def main() -> int:
    ap = argparse.ArgumentParser(description="Observe multiple Finalis lightservers and detect divergence.")
    ap.add_argument("urls", nargs="+", help="JSON-RPC endpoint URLs, e.g. http://host:19444/rpc")
    ap.add_argument("--interval", type=float, default=2.0, help="Polling interval seconds")
    ap.add_argument("--max-intervals", type=int, default=0, help="Stop after N intervals (0 = forever)")
    ap.add_argument("--mismatch-threshold", type=int, default=3, help="Exit non-zero after this many bad intervals")
    args = ap.parse_args()

    mismatch_streak = 0
    interval_count = 0

    while True:
        rows = []
        tips = []
        ids = []
        for url in args.urls:
            try:
                status = rpc(url, "get_status", {})
                tip = status.get("tip", {})
                h = int(tip["height"])
                hs = str(tip["hash"])
                network_id = str(status.get("network_id", ""))
                genesis_hash = str(status.get("genesis_hash", ""))
                proto = int(status.get("protocol_version", 0))
                magic = int(status.get("magic", 0))
                rows.append((url, h, hs, network_id, genesis_hash, proto, magic, "ok"))
                tips.append((h, hs))
                ids.append((network_id, genesis_hash, proto, magic))
            except Exception as exc:
                rows.append((url, -1, "error", "", "", 0, 0, f"err:{exc}"))
                tips.append((-1, "error"))
                ids.append(("", "", 0, 0))

        id_mismatch = False
        ref_id = None
        for identity in ids:
            if identity[0] == "":
                continue
            if ref_id is None:
                ref_id = identity
            elif identity != ref_id:
                id_mismatch = True
                break

        if id_mismatch:
            print("ERROR: chain identity mismatch detected")
            print("server\tnetwork_id\tgenesis_hash\tproto\tmagic")
            for url, _, _, nid, ghash, proto, magic, _ in rows:
                print(f"{url}\t{nid[:16]}...\t{ghash[:16]}...\t{proto}\t{magic}")
            print("")
            return 2

        best_h = max(h for h, _ in tips)
        canonical = max(tips, key=lambda t: (t[0], t[1]))
        mismatch = False

        print("server\theight\thash\tlag\tstatus")
        for url, h, hs, _, _, _, _, st in rows:
            lag = max(0, best_h - h) if h >= 0 else -1
            row_status = st
            if h >= 0 and (h, hs) != canonical:
                row_status = "mismatch"
                mismatch = True
            print(f"{url}\t{h}\t{hs[:16]}...\t{lag}\t{row_status}")
        print("")

        if mismatch:
            mismatch_streak += 1
        else:
            mismatch_streak = 0

        if mismatch_streak >= args.mismatch_threshold:
            print(f"mismatch persisted for {mismatch_streak} intervals", file=sys.stderr)
            return 2

        interval_count += 1
        if args.max_intervals > 0 and interval_count >= args.max_intervals:
            return 0

        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
