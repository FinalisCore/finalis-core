#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Write genesis.json for a public network from validator public keys.

Unlike scripts/generate_fresh_genesis.sh (devnets: generates every key on one machine), this takes
only public keys. Each operator creates their key on their own machine:

  finalis-cli --testnet wallet_create --out validator.json --pass <passphrase>

and publishes the printed pubkey_hex. Then:

  scripts/make_genesis_json.py --network testnet --pubkeys pubkeys.txt \
      --genesis-time 2026-10-20T12:00:00Z --out testnet/genesis.json
  finalis-cli genesis_build --in testnet/genesis.json --out testnet/genesis.bin

Committee and monetary parameters come from mainnet/genesis.json, so testnet rehearses mainnet.
genesis_build rejects the file if network_id or magic disagree with the compiled network.
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Must match src/common/network.cpp (kTestnetMagic and network_id_for_name).
NETWORKS = {
    "testnet": {"magic": 0x54534331, "network_id_hex": hashlib.sha256(b"finalis:testnet").hexdigest()[:32]},
}


def parse_time(value: str) -> int:
    if value.isdigit():
        return int(value)
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--network", choices=sorted(NETWORKS), required=True)
    ap.add_argument("--pubkeys", required=True, help="file with one 64-hex Ed25519 pubkey per line (# comments ok)")
    ap.add_argument("--genesis-time", required=True, help="UTC, ISO 8601 (2026-10-20T12:00:00Z) or unix seconds")
    ap.add_argument("--out", required=True)
    ap.add_argument("--note", default="")
    args = ap.parse_args()

    keys = []
    for n, line in enumerate(Path(args.pubkeys).read_text().splitlines(), 1):
        line = line.split("#", 1)[0].strip().lower()
        if not line:
            continue
        if not re.fullmatch(r"[0-9a-f]{64}", line):
            sys.exit(f"{args.pubkeys}:{n}: not a 32-byte hex pubkey: {line}")
        keys.append(line)
    if len(set(keys)) != len(keys):
        sys.exit("duplicate pubkeys")
    if not keys:
        sys.exit("no pubkeys")
    if len(keys) < 4:
        # Allowed (a bootstrap validator others join later), but it is not fault tolerant.
        print(f"warning: {len(keys)} validator(s): the chain halts if any of them stops; "
              "n >= 4 tolerates one failure", file=sys.stderr)

    doc = json.loads((ROOT / "mainnet" / "genesis.json").read_text())
    net = NETWORKS[args.network]
    doc["network_name"] = args.network
    doc["network_id_hex"] = net["network_id_hex"]
    doc["magic"] = net["magic"]
    doc["genesis_time_unix"] = parse_time(args.genesis_time)
    doc["initial_height"] = 0
    doc["initial_validators"] = keys
    doc["initial_active_set_size"] = len(keys)
    doc["seeds"] = []
    doc["note"] = args.note or f"Finalis {args.network} genesis with {len(keys)} validators"

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(doc, indent=2) + "\n")
    print(f"wrote {args.out}: network={args.network} validators={len(keys)} "
          f"genesis_time_unix={doc['genesis_time_unix']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
