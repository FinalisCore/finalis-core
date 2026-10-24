# SPDX-License-Identifier: MIT
"""Testnet validator-bond faucet: queue, limits, funding and sending, with no Discord code.

Each Discord account and each address gets one grant. A grant is the current minimum validator bond
(from `finalis-cli economics_status`) plus a small fee buffer. Grants are paid in request order, one
at a time: the next payment waits until the previous one is finalized, because the faucet's change
output is only spendable once final. While the faucet holds too little, requests wait in the queue.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import time
import urllib.request
from dataclasses import dataclass
from typing import Callable, Optional

UNITS_PER_FLS = 100_000_000
BLOCK_SECONDS = 180


def fls(units: int) -> str:
    return f"{units / UNITS_PER_FLS:,.2f} FLS"


class Rpc:
    """Lightserver JSON-RPC."""

    def __init__(self, url: str, timeout: float = 20.0):
        self.url = url
        self.timeout = timeout

    def call(self, method: str, params: dict) -> dict:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        req = urllib.request.Request(self.url, body, {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            reply = json.load(resp)
        if reply.get("error"):
            raise RuntimeError(reply["error"].get("message", "rpc error"))
        return reply["result"]

    def validate_address(self, address: str) -> dict:
        return self.call("validate_address", {"address": address})

    def balance_units(self, address: str) -> int:
        scripthash = self.validate_address(address)["scripthash_hex"]
        return sum(u["value"] for u in self.call("get_utxos", {"scripthash_hex": scripthash}))

    def tx_finalized(self, txid: str) -> bool:
        return bool(self.call("get_tx_status", {"txid": txid}).get("finalized"))


class Cli:
    """finalis-cli for the two things the RPC does not offer: the current minimum bond and signing."""

    def __init__(self, cli: str, node_db: str, key_file: str, key_pass: str, rpc_url: str):
        self.cli, self.node_db, self.key_file, self.key_pass, self.rpc_url = cli, node_db, key_file, key_pass, rpc_url

    def _run(self, args: list[str]) -> tuple[int, dict[str, str], str]:
        proc = subprocess.run([self.cli, "--testnet", *args], capture_output=True, text=True, timeout=120)
        fields = {}
        for line in proc.stdout.splitlines():
            key, sep, value = line.partition("=")
            if sep:
                fields[key.strip()] = value.strip()
        return proc.returncode, fields, (proc.stderr.strip() or proc.stdout.strip())

    def min_bond_units(self) -> int:
        code, fields, err = self._run(["economics_status", "--db", self.node_db])
        if code != 0 or "min_bond" not in fields:
            raise RuntimeError(f"economics_status failed: {err}")
        return int(fields["min_bond"])

    def send(self, address: str, units: int) -> tuple[Optional[str], bool, str]:
        """(txid, accepted, error). accepted is False also when the broadcast outcome is unknown."""
        args = ["send", "--to", address, "--amount-units", str(units), "--file", self.key_file, "--rpc", self.rpc_url]
        if self.key_pass:
            args += ["--pass", self.key_pass]
        code, fields, err = self._run(args)
        txid = fields.get("txid")
        accepted = code == 0 and fields.get("accepted") not in ("no", "unknown")
        return txid, accepted, "" if accepted else (fields.get("error_message") or err)


@dataclass
class Grant:
    id: int
    user_id: str
    address: str
    state: str  # queued | sent | done | failed
    units: int
    txid: Optional[str]
    error: Optional[str]


@dataclass
class Event:
    """Something to tell a user about."""
    user_id: str
    text: str


class Store:
    def __init__(self, path: str):
        # The bot calls in from one worker thread at a time (it holds a lock), never concurrently.
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS grants (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id TEXT NOT NULL UNIQUE,
                 address TEXT NOT NULL UNIQUE,
                 state TEXT NOT NULL,
                 units INTEGER NOT NULL DEFAULT 0,
                 txid TEXT,
                 error TEXT,
                 created REAL NOT NULL,
                 updated REAL NOT NULL)"""
        )
        self.db.commit()

    def _grant(self, row) -> Optional[Grant]:
        return Grant(*row) if row else None

    _COLS = "id, user_id, address, state, units, txid, error"

    def by_user(self, user_id: str) -> Optional[Grant]:
        return self._grant(self.db.execute(f"SELECT {self._COLS} FROM grants WHERE user_id = ?", (user_id,)).fetchone())

    def by_address(self, address: str) -> Optional[Grant]:
        return self._grant(self.db.execute(f"SELECT {self._COLS} FROM grants WHERE address = ?", (address,)).fetchone())

    def add(self, user_id: str, address: str) -> Grant:
        now = time.time()
        self.db.execute("INSERT INTO grants (user_id, address, state, created, updated) VALUES (?, ?, 'queued', ?, ?)",
                        (user_id, address, now, now))
        self.db.commit()
        return self.by_user(user_id)

    def first(self, state: str) -> Optional[Grant]:
        return self._grant(self.db.execute(f"SELECT {self._COLS} FROM grants WHERE state = ? ORDER BY id LIMIT 1",
                                           (state,)).fetchone())

    def position(self, grant: Grant) -> int:
        """1 = next to be paid."""
        return self.db.execute("SELECT COUNT(*) FROM grants WHERE state = 'queued' AND id <= ?", (grant.id,)).fetchone()[0]

    def update(self, grant_id: int, **fields) -> None:
        sets = ", ".join(f"{k} = ?" for k in fields)
        self.db.execute(f"UPDATE grants SET {sets}, updated = ? WHERE id = ?", (*fields.values(), time.time(), grant_id))
        self.db.commit()


class Faucet:
    def __init__(self, store: Store, rpc: Rpc, cli: Cli, faucet_address: str, fee_buffer_units: int,
                 income_units_per_block: int, clock: Callable[[], float] = time.time):
        self.store, self.rpc, self.cli = store, rpc, cli
        self.faucet_address = faucet_address
        self.fee_buffer_units = fee_buffer_units
        self.income_units_per_block = income_units_per_block
        self.clock = clock

    def grant_units(self) -> int:
        return self.cli.min_bond_units() + self.fee_buffer_units

    def request(self, user_id: str, address: str) -> str:
        """Reply text for a /faucet request."""
        address = address.strip()
        existing = self.store.by_user(user_id)
        if existing:
            return "You already have a grant. " + self.describe(existing)
        if self.store.by_address(address):
            return "That address already has a grant. Each address can be funded once."
        try:
            check = self.rpc.validate_address(address)
        except Exception as exc:  # RPC down or malformed reply
            return f"I couldn't check that address right now ({exc}). Please try again in a few minutes."
        if not check.get("valid"):
            return f"That is not a valid address: {check.get('error') or 'invalid'}."
        if check.get("server_network_match") is not True:
            return "That address is not a testnet address. Testnet addresses start with `tsc1`."
        grant = self.store.add(user_id, check.get("normalized_address") or address)
        return "You're in the queue. " + self.describe(grant)

    def describe(self, grant: Grant) -> str:
        if grant.state == "done":
            return (f"{fls(grant.units)} reached `{grant.address}` in tx `{grant.txid}`. "
                    "Next: `finalis-cli --testnet validator-register` (see testnet/JOIN.md, step 4.3).")
        if grant.state == "sent":
            return f"Payment `{grant.txid}` is on its way; it is final within a block or two (~3 min each)."
        if grant.state == "failed":
            return f"The payment failed ({grant.error}). The maintainer has been told."
        position = self.store.position(grant)
        try:
            need = self.grant_units() * position
            have = self.rpc.balance_units(self.faucet_address)
        except Exception:
            return f"Your place in the queue: {position}."
        if have >= need:
            return f"Your place in the queue: {position}. Funds are ready; payment goes out within a few minutes."
        blocks = -(-(need - have) // max(1, self.income_units_per_block))
        hours = blocks * BLOCK_SECONDS / 3600
        return (f"Your place in the queue: {position}. The faucet holds {fls(have)} and a bond is "
                f"{fls(self.grant_units())}, so funds for your grant arrive in about {hours:.0f} h "
                f"({blocks} blocks). I'll ping you when it is sent.")

    def tick(self) -> list[Event]:
        """One step: finish the payment in flight, or start the next one if funds allow."""
        sent = self.store.first("sent")
        if sent:
            if self.rpc.tx_finalized(sent.txid):
                self.store.update(sent.id, state="done")
                return [Event(sent.user_id, "Your validator bond is final. " + self.describe(self.store.by_user(sent.user_id)))]
            return []
        grant = self.store.first("queued")
        if not grant:
            return []
        units = self.grant_units()
        if self.rpc.balance_units(self.faucet_address) < units:
            return []
        txid, accepted, error = self.cli.send(grant.address, units)
        if accepted and txid:
            self.store.update(grant.id, state="sent", units=units, txid=txid)
            return [Event(grant.user_id, f"Sent {fls(units)} to `{grant.address}` (tx `{txid}`). "
                                         "I'll ping you again when it is final.")]
        self.store.update(grant.id, state="failed", units=units, txid=txid, error=error[:300])
        return [Event(grant.user_id, f"Sending your grant failed: {error[:300]}. The maintainer has been told.")]
