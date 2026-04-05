#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import fcntl
import hmac
import hashlib
import json
import math
import os
import random
import shlex
import ssl
import subprocess
import threading
import time
import urllib.request
import urllib.parse
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


RESERVE_MIN_CHANGE = 1000
RESERVE_MAX_INPUTS = 8
RESERVE_CONSOLIDATE_UTXO_COUNT = 12
RESERVE_FRAGMENTATION_ALERT_COUNT = 16
RESERVE_EXHAUSTION_BUFFER = 10000
RESERVE_AUTO_PAUSE_LOW_RESERVE = 10000
RESERVE_AUTO_PAUSE_LOCKED_INPUTS = 6


def sha256_hex(parts: list[str]) -> str:
    h = hashlib.sha256()
    for part in parts:
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


def read_json_body(handler: BaseHTTPRequestHandler) -> dict[str, Any] | None:
    length = handler.headers.get("Content-Length")
    if not length:
        return None
    try:
        raw = handler.rfile.read(int(length))
        body = json.loads(raw.decode("utf-8"))
        if not isinstance(body, dict):
            return None
        return body
    except Exception:
        return None


def write_json(handler: BaseHTTPRequestHandler, status: HTTPStatus, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def write_text(handler: BaseHTTPRequestHandler, status: HTTPStatus, body: str, content_type: str) -> None:
    data = body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def is_hex_of_size(value: Any, size_bytes: int) -> bool:
    return isinstance(value, str) and len(value) == size_bytes * 2 and all(c in "0123456789abcdefABCDEF" for c in value)


@dataclass
class MintConfig:
    state_file: Path
    confirmations_required: int
    signing_seed: str
    mint_id: str
    operator_keys: dict[str, bytes]
    lightserver_url: str
    reserve_privkey_hex: str
    reserve_address: str
    reserve_fee: int
    cli_path: str
    notifier_retry_interval_seconds: int
    notifier_secrets_file: Path | None
    notifier_secret_dir: Path | None
    notifier_secret_env_prefix: str
    notifier_secret_backend: str
    notifier_secret_helper_cmd: str
    worker_lock_file: Path | None
    worker_stale_timeout_seconds: int


_BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"


def decode_finalis_address(addr: str) -> bytes | None:
    if "1" not in addr:
        return None
    hrp, body = addr.split("1", 1)
    if hrp not in {"sc", "tsc"} or not body:
        return None
    rev = {c: i for i, c in enumerate(_BASE32_ALPHABET)}
    out = bytearray()
    buffer = 0
    bits = 0
    for c in body:
        if c not in rev:
            return None
        buffer = (buffer << 5) | rev[c]
        bits += 5
        if bits >= 8:
            out.append((buffer >> (bits - 8)) & 0xFF)
            bits -= 8
    if bits > 0 and (buffer & ((1 << bits) - 1)) != 0:
        return None
    if len(out) != 25 or out[0] != 0x00:
        return None
    payload = bytes(out[:21])
    chk = hashlib.sha256(hrp.encode("utf-8") + b"\x00" + payload).digest()
    chk = hashlib.sha256(chk).digest()
    if bytes(out[21:25]) != chk[:4]:
        return None
    return payload[1:21]


def p2pkh_script_pubkey(pubkey_hash: bytes) -> bytes:
    return bytes([0x76, 0xA9, 0x14]) + pubkey_hash + bytes([0x88, 0xAC])


def _is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for a in [2, 325, 9375, 28178, 450775, 9780504, 1795265022]:
        if a % n == 0:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        witness = True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                witness = False
                break
        if witness:
            return False
    return True


def _next_prime(rng: random.Random, bits: int) -> int:
    while True:
        candidate = rng.getrandbits(bits)
        candidate |= (1 << (bits - 1))
        candidate |= 1
        if _is_probable_prime(candidate):
            return candidate


def body_hash_hex(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def sign_operator_request(secret: bytes, method: str, path: str, timestamp: str, body_hash: str) -> str:
    payload = "\n".join([method.upper(), path, timestamp, body_hash]).encode("utf-8")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


@dataclass
class BlindSigner:
    n: int
    e: int
    d: int

    @classmethod
    def from_seed(cls, seed: str, bits: int = 512) -> "BlindSigner":
        rng = random.Random(int(hashlib.sha256(seed.encode("utf-8")).hexdigest(), 16))
        e = 65537
        while True:
            p = _next_prime(rng, bits)
            q = _next_prime(rng, bits)
            if p == q:
                continue
            phi = (p - 1) * (q - 1)
            if math.gcd(e, phi) == 1:
                n = p * q
                d = pow(e, -1, phi)
                return cls(n=n, e=e, d=d)

    def sign_blinded_hex(self, blinded_hex: str) -> str:
        blinded = int(blinded_hex, 16)
        if blinded <= 0 or blinded >= self.n:
            raise ValueError("blinded message out of range")
        signed = pow(blinded, self.d, self.n)
        return format(signed, "x")

    def sign_digest_hex(self, digest_hex: str) -> str:
        digest = int(digest_hex, 16)
        if digest <= 0 or digest >= self.n:
            raise ValueError("digest out of range")
        signed = pow(digest, self.d, self.n)
        return format(signed, "x")


class MintState:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._data = {
            "deposits": {},
            "issuances": {},
            "redemptions": {},
            "note_records": {},
            "consolidations": {},
            "events": [],
            "silences": [],
            "notifiers": [],
            "dead_letters": [],
            "delivery_jobs": [],
            "policy": {
                "redemptions_paused": False,
                "pause_reason": "",
                "auto_pause_enabled": False,
                "event_retention_limit": 256,
                "export_include_acknowledged": True,
                "updated_at": 0,
            },
        }
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            with self._path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self._data.update(data)
                if "spent_notes" in self._data and "note_records" not in self._data:
                    self._data["note_records"] = {
                        note: {
                            "state": "legacy-spent",
                            "redemption_batch_id": batch_id,
                            "redeem_address": "",
                            "amount": 0,
                            "updated_at": 0,
                        }
                        for note, batch_id in self._data["spent_notes"].items()
                    }
                self._data.pop("spent_notes", None)
                if "events" not in self._data or not isinstance(self._data["events"], list):
                    self._data["events"] = []
                if "silences" not in self._data or not isinstance(self._data["silences"], list):
                    self._data["silences"] = []
                if "notifiers" not in self._data or not isinstance(self._data["notifiers"], list):
                    self._data["notifiers"] = []
                if "dead_letters" not in self._data or not isinstance(self._data["dead_letters"], list):
                    self._data["dead_letters"] = []
                if "delivery_jobs" not in self._data or not isinstance(self._data["delivery_jobs"], list):
                    self._data["delivery_jobs"] = []
                policy = self._data.get("policy", {})
                if isinstance(policy, dict):
                    policy.setdefault("auto_pause_enabled", False)
                    policy.setdefault("event_retention_limit", 256)
                    policy.setdefault("export_include_acknowledged", True)
                    self._data["policy"] = policy
        except Exception:
            pass

    def _flush(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, sort_keys=True)
        os.replace(tmp, self._path)

    def register_deposit(self, deposit: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            deposit = dict(deposit)
            deposit.setdefault("issued_blind_count", 0)
            deposit.setdefault("issuance_ids", [])
            existing = self._data["deposits"].get(deposit["mint_deposit_ref"])
            if isinstance(existing, dict):
                immutable_fields = [
                    "chain",
                    "deposit_txid",
                    "deposit_vout",
                    "mint_id",
                    "recipient_pubkey_hash",
                    "amount",
                    "mint_deposit_ref",
                ]
                for field in immutable_fields:
                    if existing.get(field) != deposit.get(field):
                        raise ValueError("conflicting deposit registration")
                return dict(existing)
            self._data["deposits"][deposit["mint_deposit_ref"]] = deposit
            self._flush()
            return dict(deposit)

    def get_deposit(self, mint_deposit_ref: str) -> dict[str, Any] | None:
        with self._lock:
            dep = self._data["deposits"].get(mint_deposit_ref)
            return dict(dep) if isinstance(dep, dict) else None

    def get_note_record(self, note_ref: str) -> dict[str, Any] | None:
        with self._lock:
            item = self._data["note_records"].get(note_ref)
            return dict(item) if isinstance(item, dict) else None

    def record_issuance(
        self,
        mint_deposit_ref: str,
        blinded_messages: list[str],
        signed_blinds: list[str],
        note_amounts: list[int],
    ) -> dict[str, Any]:
        blinded_hashes = [hashlib.sha256(msg.encode("utf-8")).hexdigest() for msg in blinded_messages]
        issued_at = int(time.time())
        with self._lock:
            deposit = self._data["deposits"].get(mint_deposit_ref)
            if not isinstance(deposit, dict):
                raise KeyError("unknown mint_deposit_ref")
            if len(blinded_messages) != len(note_amounts):
                raise ValueError("note_amounts must match blinded_messages")
            if any(int(amount) <= 0 for amount in note_amounts):
                raise ValueError("note amounts must be positive")
            existing = set()
            for issuance_id in deposit.get("issuance_ids", []):
                issuance = self._data["issuances"].get(issuance_id)
                if isinstance(issuance, dict):
                    existing.update(issuance.get("blinded_hashes", []))
            overlap = existing.intersection(blinded_hashes)
            if overlap:
                raise ValueError("duplicate blinded message")
            remaining = int(deposit["amount"]) - int(deposit.get("issued_amount", 0))
            requested = sum(int(amount) for amount in note_amounts)
            if requested > remaining:
                raise ValueError("issuance exceeds deposited amount")
            issuance_id = sha256_hex([mint_deposit_ref, *blinded_hashes])
            note_refs = []
            note_entries = []
            for i, amount in enumerate(note_amounts):
                note_ref = sha256_hex([issuance_id, str(i), blinded_hashes[i]])
                note_refs.append(note_ref)
                note_entries.append(
                    {
                        "note_ref": note_ref,
                        "mint_deposit_ref": mint_deposit_ref,
                        "issuance_id": issuance_id,
                        "amount": int(amount),
                        "state": "issued",
                        "created_at": issued_at,
                        "updated_at": issued_at,
                    }
                )
            issuance = {
                "issuance_id": issuance_id,
                "mint_deposit_ref": mint_deposit_ref,
                "blinded_hashes": blinded_hashes,
                "signed_blinds": list(signed_blinds),
                "note_refs": note_refs,
                "note_amounts": [int(amount) for amount in note_amounts],
                "created_at": issued_at,
                "note_count": len(blinded_messages),
                "issued_amount": requested,
            }
            self._data["issuances"][issuance_id] = issuance
            deposit["issuance_ids"] = list(deposit.get("issuance_ids", [])) + [issuance_id]
            deposit["issued_blind_count"] = int(deposit.get("issued_blind_count", 0)) + len(blinded_messages)
            deposit["issued_amount"] = int(deposit.get("issued_amount", 0)) + requested
            self._data["deposits"][mint_deposit_ref] = deposit
            for entry in note_entries:
                self._data["note_records"][entry["note_ref"]] = entry
            self._flush()
            return dict(issuance)

    def create_redemption(self, redemption: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            policy = self._data.get("policy", {})
            if isinstance(policy, dict) and bool(policy.get("redemptions_paused", False)):
                reason = str(policy.get("pause_reason", "operator pause"))
                raise ValueError(f"redemptions paused: {reason}")
            outstanding = self._total_deposited_locked() - self._total_reserved_locked()
            if int(redemption["amount"]) > outstanding:
                raise ValueError("insufficient reserve")
            now = int(time.time())
            redemption = dict(redemption)
            redemption.setdefault("created_at", now)
            redemption["updated_at"] = now
            note_total = 0
            for note in redemption["notes"]:
                record = self._data["note_records"].get(note)
                if not isinstance(record, dict):
                    raise ValueError("unknown note")
                if record.get("state") != "issued":
                    raise ValueError("note not spendable")
                note_total += int(record.get("amount", 0))
            if note_total != int(redemption["amount"]):
                raise ValueError("redemption amount does not match note denominations")
            self._data["redemptions"][redemption["redemption_batch_id"]] = redemption
            for note in redemption["notes"]:
                record = dict(self._data["note_records"][note])
                record["state"] = redemption["state"]
                record["redemption_batch_id"] = redemption["redemption_batch_id"]
                record["redeem_address"] = redemption["redeem_address"]
                record["updated_at"] = now
                self._data["note_records"][note] = record
            self._flush()
            return dict(redemption)

    def get_redemption(self, batch_id: str) -> dict[str, Any] | None:
        with self._lock:
            item = self._data["redemptions"].get(batch_id)
            return dict(item) if isinstance(item, dict) else None

    def list_broadcast_redemptions(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                dict(item)
                for item in self._data["redemptions"].values()
                if isinstance(item, dict) and item.get("state") == "broadcast"
            ]

    def record_consolidation(self, consolidation: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            item = dict(consolidation)
            now = int(time.time())
            item.setdefault("created_at", now)
            item.setdefault("updated_at", now)
            self._data["consolidations"][item["consolidation_id"]] = item
            self._flush()
            return dict(item)

    def get_consolidation(self, consolidation_id: str) -> dict[str, Any] | None:
        with self._lock:
            item = self._data["consolidations"].get(consolidation_id)
            return dict(item) if isinstance(item, dict) else None

    def list_broadcast_consolidations(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                dict(item)
                for item in self._data["consolidations"].values()
                if isinstance(item, dict) and item.get("state") == "broadcast"
            ]

    def update_consolidation(self, consolidation_id: str, new_state: str, l1_txid: str = "",
                             metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        allowed = {
            "broadcast": {"finalized", "rejected"},
        }
        with self._lock:
            item = self._data["consolidations"].get(consolidation_id)
            if not isinstance(item, dict):
                raise KeyError("unknown consolidation_id")
            current = str(item.get("state", "broadcast"))
            if current == new_state and not metadata:
                return dict(item)
            if current not in allowed or new_state not in allowed[current]:
                if current != new_state:
                    raise ValueError("invalid consolidation state transition")
            item["state"] = new_state
            item["updated_at"] = int(time.time())
            if l1_txid:
                item["l1_txid"] = l1_txid
            if metadata:
                for key, value in metadata.items():
                    item[key] = value
            self._data["consolidations"][consolidation_id] = item
            self._flush()
            return dict(item)

    def policy(self) -> dict[str, Any]:
        with self._lock:
            item = self._data.get("policy", {})
            return dict(item) if isinstance(item, dict) else {}

    def update_policy(
        self,
        paused: bool,
        reason: str,
        auto_pause_enabled: bool | None = None,
        event_retention_limit: int | None = None,
        export_include_acknowledged: bool | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            item = dict(self._data.get("policy", {}))
            item["redemptions_paused"] = bool(paused)
            item["pause_reason"] = reason if paused else ""
            if auto_pause_enabled is not None:
                item["auto_pause_enabled"] = bool(auto_pause_enabled)
            else:
                item.setdefault("auto_pause_enabled", False)
            if event_retention_limit is not None:
                item["event_retention_limit"] = max(16, min(int(event_retention_limit), 5000))
            else:
                item.setdefault("event_retention_limit", 256)
            if export_include_acknowledged is not None:
                item["export_include_acknowledged"] = bool(export_include_acknowledged)
            else:
                item.setdefault("export_include_acknowledged", True)
            item["updated_at"] = int(time.time())
            self._data["policy"] = item
            self._flush()
            return dict(item)

    def append_event(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            item = {
                "event_id": sha256_hex([event_type, str(time.time_ns()), json.dumps(payload, sort_keys=True)]),
                "event_type": event_type,
                "payload": dict(payload),
                "deliveries": {},
                "acknowledged": False,
                "acknowledged_at": 0,
                "ack_note": "",
                "created_at": int(time.time()),
            }
            events = self._data.get("events", [])
            if not isinstance(events, list):
                events = []
            events.append(item)
            retention_limit = int(self._data.get("policy", {}).get("event_retention_limit", 256))
            retention_limit = max(16, min(retention_limit, 5000))
            self._data["events"] = events[-retention_limit:]
            self._flush()
            return dict(item)

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            events = self._data.get("events", [])
            if not isinstance(events, list):
                return []
            tail = events[-max(0, int(limit)):]
            return [dict(item) for item in reversed(tail) if isinstance(item, dict)]

    def update_event_delivery(
        self,
        event_id: str,
        notifier_id: str,
        status: str,
        attempts: int,
        last_error: str = "",
        next_retry_at: int = 0,
        delivered_at: int = 0,
    ) -> dict[str, Any]:
        with self._lock:
            events = self._data.get("events", [])
            if not isinstance(events, list):
                raise KeyError("unknown event_id")
            for idx, item in enumerate(events):
                if not isinstance(item, dict) or str(item.get("event_id", "")) != event_id:
                    continue
                updated = dict(item)
                deliveries = dict(updated.get("deliveries", {}))
                deliveries[notifier_id] = {
                    "status": status,
                    "attempts": int(attempts),
                    "last_error": last_error,
                    "next_retry_at": int(next_retry_at),
                    "delivered_at": int(delivered_at),
                    "updated_at": int(time.time()),
                }
                updated["deliveries"] = deliveries
                events[idx] = updated
                self._data["events"] = events
                self._flush()
                return dict(updated)
            raise KeyError("unknown event_id")

    def append_dead_letter(self, item: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            entry = dict(item)
            entry.setdefault("created_at", int(time.time()))
            letters = self._data.get("dead_letters", [])
            if not isinstance(letters, list):
                letters = []
            letters.append(entry)
            self._data["dead_letters"] = letters[-512:]
            self._flush()
            return dict(entry)

    def list_dead_letters(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            letters = self._data.get("dead_letters", [])
            if not isinstance(letters, list):
                return []
            tail = letters[-max(0, int(limit)):]
            return [dict(item) for item in reversed(tail) if isinstance(item, dict)]

    def remove_dead_letter(self, dead_letter_id: str) -> dict[str, Any]:
        with self._lock:
            letters = self._data.get("dead_letters", [])
            if not isinstance(letters, list):
                raise KeyError("unknown dead_letter_id")
            for idx, item in enumerate(letters):
                if isinstance(item, dict) and str(item.get("dead_letter_id", "")) == dead_letter_id:
                    removed = dict(item)
                    del letters[idx]
                    self._data["dead_letters"] = letters
                    self._flush()
                    return removed
            raise KeyError("unknown dead_letter_id")

    def enqueue_delivery_job(self, event_id: str, notifier_id: str, next_run_at: int = 0) -> dict[str, Any]:
        with self._lock:
            jobs = self._data.get("delivery_jobs", [])
            if not isinstance(jobs, list):
                jobs = []
            for item in jobs:
                if not isinstance(item, dict):
                    continue
                if str(item.get("event_id", "")) == event_id and str(item.get("notifier_id", "")) == notifier_id:
                    if str(item.get("status", "")) in {"pending", "running"}:
                        return dict(item)
            now = int(time.time())
            job = {
                "job_id": sha256_hex([event_id, notifier_id, str(time.time_ns())]),
                "event_id": event_id,
                "notifier_id": notifier_id,
                "status": "pending",
                "attempts": 0,
                "last_error": "",
                "next_run_at": int(next_run_at),
                "created_at": now,
                "updated_at": now,
            }
            jobs.append(job)
            self._data["delivery_jobs"] = jobs[-2048:]
            self._flush()
            return dict(job)

    def list_delivery_jobs(self, limit: int = 256) -> list[dict[str, Any]]:
        with self._lock:
            jobs = self._data.get("delivery_jobs", [])
            if not isinstance(jobs, list):
                return []
            tail = jobs[-max(0, int(limit)):]
            return [dict(item) for item in reversed(tail) if isinstance(item, dict)]

    def list_due_delivery_jobs(self, now_ts: int, limit: int = 64) -> list[dict[str, Any]]:
        with self._lock:
            jobs = self._data.get("delivery_jobs", [])
            if not isinstance(jobs, list):
                return []
            out: list[dict[str, Any]] = []
            for item in jobs:
                if not isinstance(item, dict):
                    continue
                if str(item.get("status", "")) != "pending":
                    continue
                if int(item.get("next_run_at", 0)) > now_ts:
                    continue
                out.append(dict(item))
                if len(out) >= limit:
                    break
            return out

    def update_delivery_job(
        self,
        job_id: str,
        status: str,
        attempts: int | None = None,
        last_error: str | None = None,
        next_run_at: int | None = None,
        delivered_at: int | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            jobs = self._data.get("delivery_jobs", [])
            if not isinstance(jobs, list):
                raise KeyError("unknown job_id")
            for idx, item in enumerate(jobs):
                if not isinstance(item, dict) or str(item.get("job_id", "")) != job_id:
                    continue
                updated = dict(item)
                updated["status"] = status
                updated["updated_at"] = int(time.time())
                if attempts is not None:
                    updated["attempts"] = int(attempts)
                if last_error is not None:
                    updated["last_error"] = last_error
                if next_run_at is not None:
                    updated["next_run_at"] = int(next_run_at)
                if delivered_at is not None:
                    updated["delivered_at"] = int(delivered_at)
                jobs[idx] = updated
                self._data["delivery_jobs"] = jobs
                self._flush()
                return dict(updated)
            raise KeyError("unknown job_id")

    def remove_delivery_job(self, job_id: str) -> None:
        with self._lock:
            jobs = self._data.get("delivery_jobs", [])
            if not isinstance(jobs, list):
                return
            self._data["delivery_jobs"] = [
                item for item in jobs if not (isinstance(item, dict) and str(item.get("job_id", "")) == job_id)
            ]
            self._flush()

    def acknowledge_event(self, event_id: str, note: str) -> dict[str, Any]:
        with self._lock:
            events = self._data.get("events", [])
            if not isinstance(events, list):
                raise KeyError("unknown event_id")
            for idx, item in enumerate(events):
                if isinstance(item, dict) and str(item.get("event_id", "")) == event_id:
                    updated = dict(item)
                    updated["acknowledged"] = True
                    updated["acknowledged_at"] = int(time.time())
                    updated["ack_note"] = note
                    events[idx] = updated
                    self._data["events"] = events
                    self._flush()
                    return dict(updated)
            raise KeyError("unknown event_id")

    def add_silence(self, event_type: str, until_ts: int, reason: str) -> dict[str, Any]:
        with self._lock:
            item = {
                "silence_id": sha256_hex([event_type, str(until_ts), reason, str(time.time_ns())]),
                "event_type": event_type,
                "until_ts": int(until_ts),
                "reason": reason,
                "created_at": int(time.time()),
                "active": True,
            }
            silences = self._data.get("silences", [])
            if not isinstance(silences, list):
                silences = []
            silences.append(item)
            self._data["silences"] = silences[-256:]
            self._flush()
            return dict(item)

    def list_silences(self, active_only: bool = False) -> list[dict[str, Any]]:
        with self._lock:
            silences = self._data.get("silences", [])
            if not isinstance(silences, list):
                return []
            now = int(time.time())
            out = []
            for item in silences:
                if not isinstance(item, dict):
                    continue
                active = bool(item.get("active", True)) and int(item.get("until_ts", 0)) > now
                row = dict(item)
                row["active"] = active
                if active_only and not active:
                    continue
                out.append(row)
            return list(reversed(out))

    def event_silenced(self, event_type: str) -> bool:
        now = int(time.time())
        with self._lock:
            silences = self._data.get("silences", [])
            if not isinstance(silences, list):
                return False
            for item in silences:
                if not isinstance(item, dict):
                    continue
                if not bool(item.get("active", True)):
                    continue
                if str(item.get("event_type", "")) != event_type:
                    continue
                if int(item.get("until_ts", 0)) > now:
                    return True
            return False

    def upsert_notifier(self, notifier: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            item = dict(notifier)
            item["updated_at"] = int(time.time())
            item.setdefault("retry_max_attempts", 3)
            item.setdefault("retry_backoff_seconds", 30)
            notifiers = self._data.get("notifiers", [])
            if not isinstance(notifiers, list):
                notifiers = []
            notifier_id = str(item.get("notifier_id", ""))
            replaced = False
            for idx, existing in enumerate(notifiers):
                if isinstance(existing, dict) and str(existing.get("notifier_id", "")) == notifier_id:
                    notifiers[idx] = item
                    replaced = True
                    break
            if not replaced:
                item.setdefault("created_at", int(time.time()))
                notifiers.append(item)
            self._data["notifiers"] = notifiers[-128:]
            self._flush()
            return dict(item)

    def list_notifiers(self) -> list[dict[str, Any]]:
        with self._lock:
            notifiers = self._data.get("notifiers", [])
            if not isinstance(notifiers, list):
                return []
            return [dict(item) for item in notifiers if isinstance(item, dict)]

    def note_already_spent(self, note: str) -> bool:
        with self._lock:
            record = self._data["note_records"].get(note)
            if not isinstance(record, dict):
                return False
            return record.get("state") != "issued"

    def update_redemption(
        self,
        batch_id: str,
        new_state: str,
        l1_txid: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        allowed = {
            "pending": {"broadcast", "finalized", "rejected"},
            "broadcast": {"finalized", "rejected"},
        }
        with self._lock:
            redemption = self._data["redemptions"].get(batch_id)
            if not isinstance(redemption, dict):
                raise KeyError("unknown redemption_batch_id")
            current = str(redemption.get("state", "pending"))
            if current == new_state and not metadata:
                return dict(redemption)
            if current not in allowed or new_state not in allowed[current]:
                if current != new_state:
                    raise ValueError("invalid redemption state transition")
            now = int(time.time())
            redemption["state"] = new_state
            redemption["updated_at"] = now
            if l1_txid:
                redemption["l1_txid"] = l1_txid
            if metadata:
                for key, value in metadata.items():
                    redemption[key] = value
            if new_state == "rejected":
                for note in redemption["notes"]:
                    record = self._data["note_records"].get(note)
                    if isinstance(record, dict):
                        record = dict(record)
                        record["state"] = "issued"
                        record.pop("redemption_batch_id", None)
                        record.pop("redeem_address", None)
                        record["updated_at"] = now
                        self._data["note_records"][note] = record
            else:
                for note in redemption["notes"]:
                    record = dict(self._data["note_records"][note])
                    record["state"] = new_state
                    record["redemption_batch_id"] = batch_id
                    record["redeem_address"] = redemption["redeem_address"]
                    record["updated_at"] = now
                    self._data["note_records"][note] = record
            self._data["redemptions"][batch_id] = redemption
            self._flush()
            return dict(redemption)

    def accounting_summary(self) -> dict[str, Any]:
        with self._lock:
            return self._accounting_summary_locked()

    def reserve_summary(self) -> dict[str, Any]:
        with self._lock:
            return self._reserve_summary_locked()

    def reserve_attestation(self, mint_id: str, inventory: dict[str, Any] | None = None) -> dict[str, Any]:
        with self._lock:
            reserve = self._reserve_summary_locked()
            attested_at = int(time.time())
            state_hash = sha256_hex(
                [
                    mint_id,
                    str(reserve["total_deposited"]),
                    str(reserve["reserved_redemption_amount"]),
                    str(reserve["finalized_redemption_amount"]),
                    str(reserve["reserve_balance"]),
                    str(reserve["available_reserve"]),
                    str((inventory or {}).get("wallet_utxo_count", 0)),
                    str((inventory or {}).get("wallet_utxo_value", 0)),
                    str((inventory or {}).get("wallet_locked_utxo_count", 0)),
                    str((inventory or {}).get("wallet_locked_utxo_value", 0)),
                    str(len(self._data["deposits"])),
                    str(len(self._data["issuances"])),
                    str(len(self._data["redemptions"])),
                    str(attested_at),
                ]
            )
            return {
                "mint_id": mint_id,
                "attested_at": attested_at,
                "state_hash": state_hash,
                **reserve,
                **(inventory or {}),
            }

    def audit_export(self, mint_id: str, inventory: dict[str, Any] | None = None) -> dict[str, Any]:
        with self._lock:
            return {
                "mint_id": mint_id,
                "deposits": list(self._data["deposits"].values()),
                "issuances": list(self._data["issuances"].values()),
                "redemptions": list(self._data["redemptions"].values()),
                "consolidations": list(self._data["consolidations"].values()),
                "note_records": list(self._data["note_records"].values()),
                "events": [
                    dict(item)
                    for item in self._data.get("events", [])
                    if isinstance(item, dict)
                    and (
                        bool(self._data.get("policy", {}).get("export_include_acknowledged", True))
                        or not bool(item.get("acknowledged", False))
                    )
                ],
                "silences": list(self._data.get("silences", [])),
                "notifiers": list(self._data.get("notifiers", [])),
                "dead_letters": list(self._data.get("dead_letters", [])),
                "delivery_jobs": list(self._data.get("delivery_jobs", [])),
                "policy": dict(self._data.get("policy", {})),
                "accounting": self._accounting_summary_locked(),
                "reserves": {**self._reserve_summary_locked(), **(inventory or {})},
            }

    def _total_deposited_locked(self) -> int:
        return sum(int(item.get("amount", 0)) for item in self._data["deposits"].values() if isinstance(item, dict))

    def _total_reserved_locked(self) -> int:
        return sum(
            int(item.get("amount", 0))
            for item in self._data["redemptions"].values()
            if isinstance(item, dict) and item.get("state") in {"pending", "broadcast", "finalized"}
        )

    def _reserve_summary_locked(self) -> dict[str, Any]:
        total_deposited = self._total_deposited_locked()
        finalized = sum(
            int(item.get("amount", 0))
            for item in self._data["redemptions"].values()
            if isinstance(item, dict) and item.get("state") == "finalized"
        )
        reserved = self._total_reserved_locked()
        spend_commitments = [
            item
            for item in self._data["redemptions"].values()
            if isinstance(item, dict) and item.get("state") == "broadcast"
        ]
        consolidations = [
            item
            for item in self._data["consolidations"].values()
            if isinstance(item, dict) and item.get("state") == "broadcast"
        ]
        return {
            "total_deposited": total_deposited,
            "reserved_redemption_amount": reserved,
            "finalized_redemption_amount": finalized,
            "reserve_balance": total_deposited - finalized,
            "available_reserve": total_deposited - reserved,
            "pending_spend_commitment_count": len(spend_commitments),
            "pending_spend_input_count": sum(len(item.get("selected_utxos", [])) for item in spend_commitments),
            "pending_consolidation_count": len(consolidations),
            "pending_consolidation_input_count": sum(len(item.get("selected_utxos", [])) for item in consolidations),
        }

    def _accounting_summary_locked(self) -> dict[str, Any]:
        total_deposited = self._total_deposited_locked()
        pending = sum(
            int(item.get("amount", 0))
            for item in self._data["redemptions"].values()
            if isinstance(item, dict) and item.get("state") == "pending"
        )
        broadcast = sum(
            int(item.get("amount", 0))
            for item in self._data["redemptions"].values()
            if isinstance(item, dict) and item.get("state") == "broadcast"
        )
        finalized = sum(
            int(item.get("amount", 0))
            for item in self._data["redemptions"].values()
            if isinstance(item, dict) and item.get("state") == "finalized"
        )
        rejected = sum(
            int(item.get("amount", 0))
            for item in self._data["redemptions"].values()
            if isinstance(item, dict) and item.get("state") == "rejected"
        )
        issuance_count = len(self._data["issuances"])
        blind_count = sum(
            int(item.get("note_count", 0)) for item in self._data["issuances"].values() if isinstance(item, dict)
        )
        return {
            "mint_id": None,
            "deposit_count": len(self._data["deposits"]),
            "issuance_count": issuance_count,
            "issued_blind_count": blind_count,
            "issued_amount": sum(
                int(item.get("issued_amount", 0)) for item in self._data["issuances"].values() if isinstance(item, dict)
            ),
            "redemption_count": len(self._data["redemptions"]),
            "active_note_locks": sum(
                1
                for item in self._data["note_records"].values()
                if isinstance(item, dict) and item.get("state") in {"pending", "broadcast", "finalized", "legacy-spent"}
            ),
            "total_deposited": total_deposited,
            "pending_redemption_amount": pending,
            "broadcast_redemption_amount": broadcast,
            "finalized_redemption_amount": finalized,
            "rejected_redemption_amount": rejected,
            "reserve_balance": total_deposited - finalized,
            "available_reserve": total_deposited - pending - broadcast - finalized,
        }


def rpc_post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    data = canonical_json_bytes(payload)
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def lightserver_finalization_depth(url: str, txid: str) -> tuple[int, int] | None:
    if not url:
        return None
    try:
        tx_resp = rpc_post_json(
            url,
            {"jsonrpc": "2.0", "id": "mint", "method": "get_tx_status", "params": {"txid": txid}},
        )
        if "error" in tx_resp or "result" not in tx_resp:
            return None
        result = tx_resp["result"]
        if not isinstance(result, dict):
            return None
        tx_height = int(result.get("height", 0))
        finalized = bool(result.get("finalized", False))
        finalization_depth = int(result.get("finalized_depth", 0)) if finalized else 0
        return tx_height, finalization_depth
    except Exception:
        return None


def lightserver_get_utxos(url: str, scripthash_hex: str) -> list[dict[str, Any]]:
    if not url:
        return []
    try:
        resp = rpc_post_json(
            url,
            {"jsonrpc": "2.0", "id": "mint", "method": "get_utxos", "params": {"scripthash_hex": scripthash_hex}},
        )
        if "error" in resp or "result" not in resp or not isinstance(resp["result"], list):
            return []
        return [item for item in resp["result"] if isinstance(item, dict)]
    except Exception:
        return []


def lightserver_broadcast_tx(url: str, tx_hex: str) -> tuple[bool, str]:
    if not url:
        return False, "lightserver url not configured"
    try:
        resp = rpc_post_json(
            url,
            {"jsonrpc": "2.0", "id": "mint", "method": "broadcast_tx", "params": {"tx_hex": tx_hex}},
        )
        if "error" in resp or "result" not in resp or not isinstance(resp["result"], dict):
            return False, "broadcast rpc failed"
        if not bool(resp["result"].get("accepted", False)):
            return False, str(resp["result"].get("error", "tx rejected"))
        return True, str(resp["result"].get("txid", ""))
    except Exception as exc:
        return False, str(exc)


def _sum_utxo_values(utxos: list[dict[str, Any]]) -> int:
    return sum(int(item.get("value", 0)) for item in utxos if isinstance(item, dict))


def parse_operator_keys(entries: list[str]) -> dict[str, bytes]:
    if not entries:
        return {"dev-operator": hashlib.sha256(b"dev-operator-secret").digest()}
    out: dict[str, bytes] = {}
    for entry in entries:
        if ":" not in entry:
            raise ValueError("operator key must be key_id:hex_secret")
        key_id, secret_hex = entry.split(":", 1)
        key_id = key_id.strip()
        if not key_id:
            raise ValueError("operator key id cannot be empty")
        try:
            secret = bytes.fromhex(secret_hex)
        except ValueError as exc:
            raise ValueError("operator secret must be hex") from exc
        if len(secret) < 16:
            raise ValueError("operator secret must be at least 16 bytes")
        out[key_id] = secret
    return out


def load_notifier_secrets(path: Path | None) -> dict[str, str]:
    if path is None or not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return {str(k): str(v) for k, v in data.items() if isinstance(k, str) and isinstance(v, str)}
    except Exception:
        return {}


def load_notifier_secret_from_path(secret_dir: Path | None, ref: str) -> str:
    if secret_dir is None or not ref:
        return ""
    try:
        if "/" in ref or "\\" in ref or ".." in ref:
            return ""
        path = secret_dir / ref
        if not path.exists() or not path.is_file():
            return ""
        return path.read_text(encoding="utf-8").strip()
    except Exception:
        return ""


class SecretBackendAdapter:
    def __init__(self, config: MintConfig) -> None:
        self._config = config

    def resolve(self, ref: str) -> str:
        if not ref:
            return ""
        backend = self._config.notifier_secret_backend
        if backend == "dir":
            return load_notifier_secret_from_path(self._config.notifier_secret_dir, ref)
        if backend == "env":
            env_key = f"{self._config.notifier_secret_env_prefix}{ref}".upper()
            return os.environ.get(env_key, "")
        if backend == "json":
            return load_notifier_secrets(self._config.notifier_secrets_file).get(ref, "")
        if backend == "command":
            helper = self._config.notifier_secret_helper_cmd.strip()
            if not helper:
                return ""
            try:
                cmd = shlex.split(helper) + [ref]
                proc = subprocess.run(cmd, check=True, text=True, capture_output=True)
                return proc.stdout.strip()
            except Exception:
                return ""
        # auto
        value = load_notifier_secret_from_path(self._config.notifier_secret_dir, ref)
        if value:
            return value
        env_key = f"{self._config.notifier_secret_env_prefix}{ref}".upper()
        value = os.environ.get(env_key, "")
        if value:
            return value
        value = load_notifier_secrets(self._config.notifier_secrets_file).get(ref, "")
        if value:
            return value
        if self._config.notifier_secret_helper_cmd.strip():
            try:
                cmd = shlex.split(self._config.notifier_secret_helper_cmd.strip()) + [ref]
                proc = subprocess.run(cmd, check=True, text=True, capture_output=True)
                return proc.stdout.strip()
            except Exception:
                return ""
        return ""


class WorkerLeaderLock:
    def __init__(self, path: Path | None, stale_timeout_seconds: int = 30) -> None:
        self._path = path
        self._control_path = path.with_suffix(".ctl") if path is not None else None
        self._owned = False
        self._stale_timeout_seconds = max(5, int(stale_timeout_seconds))
        self._owner_pid = os.getpid()
        self._acquired_at = 0

    def _with_control_lock(self, fn):
        if self._control_path is None:
            return fn()
        self._control_path.parent.mkdir(parents=True, exist_ok=True)
        with self._control_path.open("a+", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                return fn()
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    def _read_state(self) -> dict[str, Any]:
        if self._path is None or not self._path.exists():
            return {}
        try:
            with self._path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _write_state(self, mode: str) -> None:
        if self._path is None:
            return
        now = int(time.time())
        state = {
            "owner_pid": self._owner_pid,
            "heartbeat_at": now,
            "acquired_at": self._acquired_at or now,
            "mode": mode,
            "stale_timeout_seconds": self._stale_timeout_seconds,
        }
        tmp = self._path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(state, f, sort_keys=True)
        os.replace(tmp, self._path)

    def _state_stale(self, state: dict[str, Any], now_ts: int | None = None) -> bool:
        if not state:
            return True
        now = int(time.time()) if now_ts is None else int(now_ts)
        heartbeat = int(state.get("heartbeat_at", 0))
        timeout = max(5, int(state.get("stale_timeout_seconds", self._stale_timeout_seconds)))
        return heartbeat <= 0 or (now - heartbeat) > timeout

    def acquire_status(self, mode: str = "worker") -> dict[str, Any]:
        if self._path is None:
            if self._acquired_at == 0:
                self._acquired_at = int(time.time())
            self._owned = True
            return {"acquired": True, "takeover": False, "stale_owner_pid": "", "reason": "no-lock-file"}

        def _acquire() -> dict[str, Any]:
            state = self._read_state()
            stale = self._state_stale(state)
            current_owner = int(state.get("owner_pid", -1)) if state else -1
            stale_owner_pid = str(state.get("owner_pid", "")) if stale and state else ""
            if state and not stale and current_owner != self._owner_pid:
                self._owned = False
                return {"acquired": False, "takeover": False, "stale_owner_pid": "", "reason": "lease-held"}
            takeover = bool(state) and stale and current_owner != self._owner_pid
            if self._acquired_at == 0:
                self._acquired_at = int(time.time())
            self._owned = True
            self._write_state(mode)
            return {
                "acquired": True,
                "takeover": takeover,
                "stale_owner_pid": stale_owner_pid,
                "reason": "takeover" if takeover else "acquired",
            }

        return dict(self._with_control_lock(_acquire))

    def try_acquire(self, mode: str = "worker") -> bool:
        return bool(self.acquire_status(mode).get("acquired", False))

    def heartbeat(self, mode: str = "worker") -> None:
        if not self._owned:
            return
        if self._path is None:
            return

        def _heartbeat() -> None:
            state = self._read_state()
            if state and int(state.get("owner_pid", -1)) != self._owner_pid and not self._state_stale(state):
                self._owned = False
                return
            self._write_state(mode)

        self._with_control_lock(_heartbeat)

    def release(self) -> None:
        if self._path is None:
            self._owned = False
            return

        def _release() -> None:
            state = self._read_state()
            if state and int(state.get("owner_pid", -1)) == self._owner_pid and self._path is not None and self._path.exists():
                try:
                    self._path.unlink()
                except FileNotFoundError:
                    pass
            self._owned = False

        self._with_control_lock(_release)

    def status(self) -> dict[str, Any]:
        state = self._read_state()
        stale = self._state_stale(state)
        return {
            "lock_file": str(self._path) if self._path is not None else "",
            "owned": self._owned,
            "owner_pid": str(state.get("owner_pid", "")),
            "heartbeat_at": int(state.get("heartbeat_at", 0)) if state else 0,
            "acquired_at": int(state.get("acquired_at", 0)) if state else 0,
            "stale": stale,
            "stale_timeout_seconds": self._stale_timeout_seconds,
            "takeover_policy": "allow-after-stale-timeout",
            "mode": str(state.get("mode", "")) if state else "",
        }


def sign_snapshot(attestor: BlindSigner, payload: dict[str, Any], operator_key_id: str) -> dict[str, Any]:
    body = canonical_json_bytes(payload)
    digest_hex = hashlib.sha256(body).hexdigest()
    return {
        "payload": payload,
        "payload_sha256": digest_hex,
        "signature_hex": attestor.sign_digest_hex(digest_hex),
        "signature_scheme": "rsa-sha256-raw",
        "operator_key_id": operator_key_id,
    }


def build_redemption_tx(config: MintConfig, utxos: list[dict[str, Any]], redeem_address: str, amount: int) -> tuple[str, str]:
    cmd = [
        config.cli_path,
        "build_p2pkh_multi_tx",
        "--from-privkey",
        config.reserve_privkey_hex,
        "--to-address",
        redeem_address,
        "--amount",
        str(amount),
        "--fee",
        str(config.reserve_fee),
        "--change-address",
        config.reserve_address,
    ]
    for utxo in utxos:
        cmd.extend(
            [
                "--prev-txid",
                str(utxo["txid"]),
                "--prev-index",
                str(int(utxo["vout"])),
                "--prev-value",
                str(int(utxo["value"])),
            ]
        )
    proc = subprocess.run(cmd, check=True, text=True, capture_output=True)
    txid = ""
    tx_hex = ""
    for line in proc.stdout.splitlines():
        if line.startswith("txid="):
            txid = line.split("=", 1)[1]
        elif line.startswith("tx_hex="):
            tx_hex = line.split("=", 1)[1]
    if not txid or not tx_hex:
        raise RuntimeError("build_p2pkh_tx did not return txid/tx_hex")
    return txid, tx_hex


def _html_escape(value: Any) -> str:
    text = str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def make_handler(config: MintConfig, state: MintState, signer: BlindSigner, attestor: BlindSigner, primary_operator_key_id: str, leader_lock: WorkerLeaderLock | None = None):
    secret_backend = SecretBackendAdapter(config)
    class MintHandler(BaseHTTPRequestHandler):
        server_version = "finalis-mint/0.1"

        def log_message(self, fmt: str, *args: Any) -> None:
            return

        def _notifier_secret(self, notifier: dict[str, Any], ref_key: str, direct_key: str) -> str:
            ref = str(notifier.get(ref_key, ""))
            if ref:
                return secret_backend.resolve(ref)
            return str(notifier.get(direct_key, ""))

        def _worker_status(self) -> dict[str, Any]:
            if leader_lock is None:
                return {
                    "mode": "standalone",
                    "lock_file": "",
                    "owned": False,
                    "owner_pid": "",
                }
            status = leader_lock.status()
            status["mode"] = "lock-managed"
            return status

        def _require_operator(self, raw_body: bytes) -> bool:
            key_id = self.headers.get("X-Finalis-Operator-Key", "")
            timestamp = self.headers.get("X-Finalis-Timestamp", "")
            signature = self.headers.get("X-Finalis-Signature", "")
            if not key_id or not timestamp or not signature:
                write_json(self, HTTPStatus.UNAUTHORIZED, {"error": "operator auth required"})
                return False
            secret = config.operator_keys.get(key_id)
            if secret is None:
                write_json(self, HTTPStatus.UNAUTHORIZED, {"error": "unknown operator key"})
                return False
            try:
                ts = int(timestamp)
            except ValueError:
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid operator timestamp"})
                return False
            if abs(int(time.time()) - ts) > 300:
                write_json(self, HTTPStatus.UNAUTHORIZED, {"error": "stale operator timestamp"})
                return False
            expected = sign_operator_request(secret, self.command, self.path, timestamp, body_hash_hex(raw_body))
            if not hmac.compare_digest(expected, signature):
                write_json(self, HTTPStatus.UNAUTHORIZED, {"error": "bad operator signature"})
                return False
            return True

        def _reconcile_redemption(self, batch_id: str) -> None:
            redemption = state.get_redemption(batch_id)
            if not isinstance(redemption, dict):
                return
            if redemption.get("state") != "broadcast":
                return
            observed_spent = self._reserve_outpoints_missing_from_lightserver(redemption.get("selected_utxos", []))
            if observed_spent and not redemption.get("network_spend_observed", False):
                state.update_redemption(
                    batch_id,
                    "broadcast",
                    str(redemption.get("l1_txid", "")),
                    {
                        "network_spend_observed": True,
                        "network_spend_observed_at": int(time.time()),
                    },
                )
            txid = str(redemption.get("l1_txid", ""))
            if not txid:
                return
            observed = lightserver_finalization_depth(config.lightserver_url, txid)
            if observed is None:
                return
            _, finalization_depth = observed
            if finalization_depth >= config.confirmations_required:
                state.update_redemption(batch_id, "finalized", txid)

        def _reconcile_consolidation(self, consolidation_id: str) -> None:
            item = state.get_consolidation(consolidation_id)
            if not isinstance(item, dict):
                return
            if item.get("state") != "broadcast":
                return
            observed_spent = self._reserve_outpoints_missing_from_lightserver(item.get("selected_utxos", []))
            if observed_spent and not item.get("network_spend_observed", False):
                state.update_consolidation(
                    consolidation_id,
                    "broadcast",
                    str(item.get("l1_txid", "")),
                    {
                        "network_spend_observed": True,
                        "network_spend_observed_at": int(time.time()),
                    },
                )
            txid = str(item.get("l1_txid", ""))
            if not txid:
                return
            observed = lightserver_finalization_depth(config.lightserver_url, txid)
            if observed is None:
                return
            _, finalization_depth = observed
            if finalization_depth >= config.confirmations_required:
                state.update_consolidation(consolidation_id, "finalized", txid)

        def _reconcile_all_broadcast(self) -> None:
            for redemption in state.list_broadcast_redemptions():
                batch_id = redemption.get("redemption_batch_id")
                if isinstance(batch_id, str):
                    self._reconcile_redemption(batch_id)
            for consolidation in state.list_broadcast_consolidations():
                consolidation_id = consolidation.get("consolidation_id")
                if isinstance(consolidation_id, str):
                    self._reconcile_consolidation(consolidation_id)

        def _locked_reserve_outpoints(self) -> set[tuple[str, int]]:
            locked: set[tuple[str, int]] = set()
            for redemption in state.list_broadcast_redemptions():
                for utxo in redemption.get("selected_utxos", []):
                    if isinstance(utxo, dict):
                        txid = str(utxo.get("txid", ""))
                        vout = int(utxo.get("vout", -1))
                        if txid and vout >= 0:
                            locked.add((txid, vout))
            for consolidation in state.list_broadcast_consolidations():
                for utxo in consolidation.get("selected_utxos", []):
                    if isinstance(utxo, dict):
                        txid = str(utxo.get("txid", ""))
                        vout = int(utxo.get("vout", -1))
                        if txid and vout >= 0:
                            locked.add((txid, vout))
            return locked

        def _reserve_raw_utxos(self) -> list[dict[str, Any]]:
            if not config.lightserver_url or not config.reserve_address:
                return []
            reserve_pkh = decode_finalis_address(config.reserve_address)
            if reserve_pkh is None:
                return []
            reserve_scripthash = hashlib.sha256(p2pkh_script_pubkey(reserve_pkh)).hexdigest()
            return lightserver_get_utxos(config.lightserver_url, reserve_scripthash)

        def _reserve_outpoints_missing_from_lightserver(self, selected_utxos: list[dict[str, Any]]) -> bool:
            if not selected_utxos:
                return False
            current = {
                (str(item.get("txid", "")), int(item.get("vout", -1)))
                for item in self._reserve_raw_utxos()
            }
            needed = {
                (str(item.get("txid", "")), int(item.get("vout", -1)))
                for item in selected_utxos
                if isinstance(item, dict)
            }
            return bool(needed) and needed.isdisjoint(current)

        def _pending_network_spend_observation(self) -> dict[str, int]:
            redemptions = state.list_broadcast_redemptions()
            consolidations = state.list_broadcast_consolidations()
            redemption_seen = sum(
                1 for item in redemptions if self._reserve_outpoints_missing_from_lightserver(item.get("selected_utxos", []))
            )
            consolidation_seen = sum(
                1 for item in consolidations if self._reserve_outpoints_missing_from_lightserver(item.get("selected_utxos", []))
            )
            return {
                "pending_spend_network_observed_count": redemption_seen,
                "pending_consolidation_network_observed_count": consolidation_seen,
            }

        def _reserve_alerts(self, summary: dict[str, Any], inventory: dict[str, Any]) -> dict[str, Any]:
            utxo_count = int(inventory.get("wallet_utxo_count", 0))
            utxo_value = int(inventory.get("wallet_utxo_value", 0))
            below_min = int(inventory.get("wallet_fragment_below_min_change", 0))
            available_reserve = int(summary.get("available_reserve", 0))
            recommend_consolidation = utxo_count >= RESERVE_CONSOLIDATE_UTXO_COUNT or below_min > 0
            return {
                "coin_selection_policy": "smallest-sufficient-non-dust-change",
                "coin_selection_max_inputs": RESERVE_MAX_INPUTS,
                "coin_selection_min_change": RESERVE_MIN_CHANGE,
                "consolidation_threshold_utxos": RESERVE_CONSOLIDATE_UTXO_COUNT,
                "fragmentation_alert_threshold_utxos": RESERVE_FRAGMENTATION_ALERT_COUNT,
                "reserve_exhaustion_buffer": RESERVE_EXHAUSTION_BUFFER,
                "recommend_consolidation": recommend_consolidation,
                "consolidation_candidate_count": below_min,
                "alert_max_inputs_pressure": utxo_count > RESERVE_MAX_INPUTS,
                "alert_fragmentation_threshold_breach": utxo_count >= RESERVE_FRAGMENTATION_ALERT_COUNT,
                "alert_reserve_exhaustion_risk": available_reserve <= RESERVE_EXHAUSTION_BUFFER or utxo_value <= RESERVE_EXHAUSTION_BUFFER,
            }

        def _policy_recommendations(self, summary: dict[str, Any], inventory: dict[str, Any], alerts: dict[str, Any]) -> dict[str, Any]:
            reasons: list[str] = []
            if bool(alerts.get("alert_reserve_exhaustion_risk", False)):
                reasons.append("reserve exhaustion risk")
            if int(inventory.get("wallet_locked_utxo_count", 0)) >= RESERVE_AUTO_PAUSE_LOCKED_INPUTS:
                reasons.append("too many reserve utxos already locked")
            if int(summary.get("available_reserve", 0)) <= RESERVE_AUTO_PAUSE_LOW_RESERVE:
                reasons.append("available reserve below operator buffer")
            return {
                "auto_pause_recommended": bool(reasons),
                "auto_pause_reason": ", ".join(reasons),
                "auto_pause_thresholds": {
                    "available_reserve_lte": RESERVE_AUTO_PAUSE_LOW_RESERVE,
                    "wallet_locked_utxo_count_gte": RESERVE_AUTO_PAUSE_LOCKED_INPUTS,
                    "reserve_exhaustion_buffer": RESERVE_EXHAUSTION_BUFFER,
                },
            }

        def _reserve_health_summary(self, summary: dict[str, Any], inventory: dict[str, Any], alerts: dict[str, Any]) -> dict[str, Any]:
            policy = self._policy_recommendations(summary, inventory, alerts)
            status = "healthy"
            if policy["auto_pause_recommended"] or bool(alerts.get("alert_reserve_exhaustion_risk", False)):
                status = "critical"
            elif bool(alerts.get("alert_fragmentation_threshold_breach", False)) or bool(alerts.get("alert_max_inputs_pressure", False)):
                status = "warn"
            return {
                "status": status,
                "available_reserve": int(summary.get("available_reserve", 0)),
                "reserve_balance": int(summary.get("reserve_balance", 0)),
                "wallet_utxo_count": int(inventory.get("wallet_utxo_count", 0)),
                "wallet_utxo_value": int(inventory.get("wallet_utxo_value", 0)),
                "wallet_locked_utxo_count": int(inventory.get("wallet_locked_utxo_count", 0)),
                "wallet_fragment_below_min_change": int(inventory.get("wallet_fragment_below_min_change", 0)),
                "pending_spend_commitment_count": int(summary.get("pending_spend_commitment_count", 0)),
                "pending_consolidation_count": int(summary.get("pending_consolidation_count", 0)),
                "alerts": {
                    "reserve_exhaustion_risk": bool(alerts.get("alert_reserve_exhaustion_risk", False)),
                    "fragmentation_threshold_breach": bool(alerts.get("alert_fragmentation_threshold_breach", False)),
                    "max_inputs_pressure": bool(alerts.get("alert_max_inputs_pressure", False)),
                    "recommend_consolidation": bool(alerts.get("recommend_consolidation", False)),
                    "auto_pause_recommended": bool(policy.get("auto_pause_recommended", False)),
                },
                "policy": policy,
                "worker": self._worker_status(),
                "updated_at": int(time.time()),
            }

        def _metrics_payload(self, summary: dict[str, Any], inventory: dict[str, Any], alerts: dict[str, Any]) -> str:
            policy = self._policy_recommendations(summary, inventory, alerts)
            health = self._reserve_health_summary(summary, inventory, alerts)
            pending_delivery = 0
            delivered_count = 0
            dead_letter_count = 0
            latency_sum = 0
            for event in state.list_events(256):
                deliveries = event.get("deliveries", {})
                if isinstance(deliveries, dict):
                    for item in deliveries.values():
                        if not isinstance(item, dict):
                            continue
                        status = str(item.get("status", ""))
                        if status == "pending":
                            pending_delivery += 1
                        elif status == "delivered":
                            delivered_count += 1
                            delivered_at = int(item.get("delivered_at", 0))
                            created_at = int(event.get("created_at", 0))
                            if delivered_at > 0 and created_at > 0 and delivered_at >= created_at:
                                latency_sum += delivered_at - created_at
                        elif status == "dead_letter":
                            dead_letter_count += 1
            success_rate = 0.0
            finished = delivered_count + dead_letter_count
            if finished > 0:
                success_rate = delivered_count / float(finished)
            avg_latency = 0.0
            if delivered_count > 0:
                avg_latency = latency_sum / float(delivered_count)
            lines = [
                "# TYPE finalis_mint_available_reserve gauge",
                f"finalis_mint_available_reserve {int(summary.get('available_reserve', 0))}",
                "# TYPE finalis_mint_reserve_balance gauge",
                f"finalis_mint_reserve_balance {int(summary.get('reserve_balance', 0))}",
                "# TYPE finalis_mint_wallet_utxo_count gauge",
                f"finalis_mint_wallet_utxo_count {int(inventory.get('wallet_utxo_count', 0))}",
                "# TYPE finalis_mint_wallet_locked_utxo_count gauge",
                f"finalis_mint_wallet_locked_utxo_count {int(inventory.get('wallet_locked_utxo_count', 0))}",
                "# TYPE finalis_mint_pending_spend_commitment_count gauge",
                f"finalis_mint_pending_spend_commitment_count {int(summary.get('pending_spend_commitment_count', 0))}",
                "# TYPE finalis_mint_pending_consolidation_count gauge",
                f"finalis_mint_pending_consolidation_count {int(summary.get('pending_consolidation_count', 0))}",
                "# TYPE finalis_mint_alert_reserve_exhaustion_risk gauge",
                f"finalis_mint_alert_reserve_exhaustion_risk {1 if bool(alerts.get('alert_reserve_exhaustion_risk', False)) else 0}",
                "# TYPE finalis_mint_alert_fragmentation_threshold_breach gauge",
                f"finalis_mint_alert_fragmentation_threshold_breach {1 if bool(alerts.get('alert_fragmentation_threshold_breach', False)) else 0}",
                "# TYPE finalis_mint_alert_max_inputs_pressure gauge",
                f"finalis_mint_alert_max_inputs_pressure {1 if bool(alerts.get('alert_max_inputs_pressure', False)) else 0}",
                "# TYPE finalis_mint_auto_pause_recommended gauge",
                f"finalis_mint_auto_pause_recommended {1 if bool(policy.get('auto_pause_recommended', False)) else 0}",
                "# TYPE finalis_mint_redemptions_paused gauge",
                f"finalis_mint_redemptions_paused {1 if bool(state.policy().get('redemptions_paused', False)) else 0}",
                "# TYPE finalis_mint_auto_pause_enabled gauge",
                f"finalis_mint_auto_pause_enabled {1 if bool(state.policy().get('auto_pause_enabled', False)) else 0}",
                "# TYPE finalis_mint_health_status gauge",
                f"finalis_mint_health_status {2 if health['status'] == 'critical' else 1 if health['status'] == 'warn' else 0}",
                "# TYPE finalis_mint_event_log_size gauge",
                f"finalis_mint_event_log_size {len(state.list_events(256))}",
                "# TYPE finalis_mint_dead_letter_count gauge",
                f"finalis_mint_dead_letter_count {len(state.list_dead_letters(512))}",
                "# TYPE finalis_mint_pending_notifier_delivery_count gauge",
                f"finalis_mint_pending_notifier_delivery_count {pending_delivery}",
                "# TYPE finalis_mint_delivery_job_queue_size gauge",
                f"finalis_mint_delivery_job_queue_size {len(state.list_delivery_jobs(2048))}",
                "# TYPE finalis_mint_worker_leader_owned gauge",
                f"finalis_mint_worker_leader_owned {1 if bool(self._worker_status().get('owned', False)) else 0}",
                "# TYPE finalis_mint_notifier_delivered_count gauge",
                f"finalis_mint_notifier_delivered_count {delivered_count}",
                "# TYPE finalis_mint_notifier_success_rate gauge",
                f"finalis_mint_notifier_success_rate {success_rate:.6f}",
                "# TYPE finalis_mint_notifier_delivery_latency_seconds_avg gauge",
                f"finalis_mint_notifier_delivery_latency_seconds_avg {avg_latency:.6f}",
            ]
            return "\n".join(lines) + "\n"

        def _notifier_request(self, notifier: dict[str, Any], body: bytes, content_type: str) -> None:
            url = str(notifier.get("target", ""))
            if not url:
                return
            headers = {"Content-Type": content_type}
            auth_type = str(notifier.get("auth_type", "none"))
            if auth_type == "bearer":
                token = self._notifier_secret(notifier, "auth_token_secret_ref", "auth_token")
                if token:
                    headers["Authorization"] = f"Bearer {token}"
            elif auth_type == "basic":
                user = self._notifier_secret(notifier, "auth_user_secret_ref", "auth_user")
                password = self._notifier_secret(notifier, "auth_pass_secret_ref", "auth_pass")
                raw = f"{user}:{password}".encode("utf-8")
                headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            parsed = urllib.parse.urlparse(url)
            context = None
            if parsed.scheme == "https":
                if bool(notifier.get("tls_verify", True)):
                    context = ssl.create_default_context()
                    ca_file = str(notifier.get("tls_ca_file", ""))
                    if ca_file:
                        context.load_verify_locations(cafile=ca_file)
                else:
                    context = ssl._create_unverified_context()
                client_cert = str(notifier.get("tls_client_cert_file", ""))
                client_key = str(notifier.get("tls_client_key_file", ""))
                if client_cert:
                    context.load_cert_chain(client_cert, keyfile=client_key or None)
            with urllib.request.urlopen(req, timeout=3, context=context):
                pass

        def _dispatch_notifier(self, notifier: dict[str, Any], event: dict[str, Any]) -> None:
            if not bool(notifier.get("enabled", True)):
                return
            kind = str(notifier.get("kind", ""))
            if kind == "webhook":
                self._notifier_request(notifier, canonical_json_bytes({"event": event}), "application/json")
                return
            if kind == "alertmanager":
                payload = [{
                    "labels": {
                        "alertname": str(event.get("event_type", "finalis_mint_event")),
                        "service": "finalis-mint",
                    },
                    "annotations": {
                        "event_id": str(event.get("event_id", "")),
                        "note": str(event.get("ack_note", "")),
                        "payload": json.dumps(event.get("payload", {}), sort_keys=True),
                    },
                    "startsAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(event.get("created_at", 0)))),
                }]
                self._notifier_request(notifier, canonical_json_bytes({"alerts": payload}), "application/json")
                return
            if kind == "email_spool":
                spool_dir = str(notifier.get("target", ""))
                if not spool_dir:
                    return
                to_addr = str(notifier.get("email_to", "ops@example.invalid"))
                from_addr = str(notifier.get("email_from", "finalis-mint@example.invalid"))
                path = Path(spool_dir)
                path.mkdir(parents=True, exist_ok=True)
                subject = f"[finalis-mint] {event.get('event_type', 'event')}"
                body = (
                    f"From: {from_addr}\n"
                    f"To: {to_addr}\n"
                    f"Subject: {subject}\n\n"
                    f"{json.dumps(event, indent=2, sort_keys=True)}\n"
                )
                out = path / f"{event.get('event_id', 'event')}.eml"
                out.write_text(body, encoding="utf-8")
                return

        def _deliver_event_to_notifier(self, notifier: dict[str, Any], event: dict[str, Any], job: dict[str, Any] | None = None) -> dict[str, Any]:
            notifier_id = str(notifier.get("notifier_id", ""))
            existing = event.get("deliveries", {})
            attempts = int(job.get("attempts", 0)) + 1 if isinstance(job, dict) else int(dict(existing.get(notifier_id, {})).get("attempts", 0)) + 1
            max_attempts = max(1, int(notifier.get("retry_max_attempts", 3)))
            backoff = max(1, int(notifier.get("retry_backoff_seconds", 30)))
            try:
                self._dispatch_notifier(notifier, event)
                updated = state.update_event_delivery(
                    str(event.get("event_id", "")),
                    notifier_id,
                    "delivered",
                    attempts,
                    delivered_at=int(time.time()),
                )
                if isinstance(job, dict):
                    state.update_delivery_job(str(job.get("job_id", "")), "done", attempts=attempts, delivered_at=int(time.time()))
                return updated
            except Exception as exc:
                last_error = str(exc)
                if attempts >= max_attempts:
                    state.append_dead_letter(
                        {
                            "dead_letter_id": sha256_hex([str(event.get("event_id", "")), notifier_id, str(time.time_ns())]),
                            "event_id": str(event.get("event_id", "")),
                            "notifier_id": notifier_id,
                            "event_type": str(event.get("event_type", "")),
                            "last_error": last_error,
                            "attempts": attempts,
                            "payload": dict(event.get("payload", {})),
                        }
                    )
                    updated = state.update_event_delivery(
                        str(event.get("event_id", "")),
                        notifier_id,
                        "dead_letter",
                        attempts,
                        last_error=last_error,
                    )
                    if isinstance(job, dict):
                        state.update_delivery_job(str(job.get("job_id", "")), "dead_letter", attempts=attempts, last_error=last_error)
                    return updated
                next_retry_at = int(time.time()) + backoff * (2 ** (attempts - 1))
                updated = state.update_event_delivery(
                    str(event.get("event_id", "")),
                    notifier_id,
                    "pending",
                    attempts,
                    last_error=last_error,
                    next_retry_at=next_retry_at,
                )
                if isinstance(job, dict):
                    state.update_delivery_job(
                        str(job.get("job_id", "")),
                        "pending",
                        attempts=attempts,
                        last_error=last_error,
                        next_run_at=next_retry_at,
                    )
                return updated

        def _process_delivery_jobs(self, limit: int = 32) -> None:
            now = int(time.time())
            jobs = state.list_due_delivery_jobs(now, limit)
            if not jobs:
                return
            notifiers = {str(item.get("notifier_id", "")): item for item in state.list_notifiers()}
            events = {str(item.get("event_id", "")): item for item in state.list_events(512)}
            for job in jobs:
                job_id = str(job.get("job_id", ""))
                notifier_id = str(job.get("notifier_id", ""))
                event_id = str(job.get("event_id", ""))
                notifier = notifiers.get(notifier_id)
                event = events.get(event_id)
                if not isinstance(notifier, dict) or not isinstance(event, dict):
                    state.update_delivery_job(job_id, "dead_letter", attempts=int(job.get("attempts", 0)), last_error="queue target missing")
                    continue
                state.update_delivery_job(job_id, "running", attempts=int(job.get("attempts", 0)))
                updated = self._deliver_event_to_notifier(notifier, event, job)
                deliveries = updated.get("deliveries", {})
                delivery = dict(deliveries.get(notifier_id, {})) if isinstance(deliveries, dict) else {}
                if str(delivery.get("status", "")) == "delivered":
                    state.remove_delivery_job(job_id)

        def _record_event(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
            event = state.append_event(event_type, payload)
            if state.event_silenced(event_type):
                return event
            for notifier in state.list_notifiers():
                notifier_id = str(notifier.get("notifier_id", ""))
                state.update_event_delivery(str(event.get("event_id", "")), notifier_id, "pending", 0, next_retry_at=0)
                state.enqueue_delivery_job(str(event.get("event_id", "")), notifier_id, 0)
            return event

        def _dashboard_html(self, title: str, body: str) -> str:
            return (
                "<!doctype html><html><head><meta charset='utf-8'><title>"
                + _html_escape(title)
                + "</title><style>body{font-family:ui-monospace,monospace;margin:24px;background:#f6f2e8;color:#1f1a14}"
                  "h1,h2{margin:0 0 12px}table{border-collapse:collapse;width:100%;margin:16px 0}th,td{border:1px solid #c7baa6;padding:6px 8px;text-align:left;vertical-align:top}"
                  ".chip{display:inline-block;padding:2px 8px;border-radius:999px;background:#ddd}.crit{background:#e58f7c}.warn{background:#f2cf7a}.ok{background:#a8d5a2}</style></head><body>"
                + body
                + "</body></html>"
            )

        def _dashboard_index(self) -> str:
            summary = state.reserve_summary()
            inventory = self._reserve_inventory()
            alerts = self._reserve_alerts(summary, inventory)
            health = self._reserve_health_summary(summary, inventory, alerts)
            policy = state.policy()
            jobs = state.list_delivery_jobs(20)
            events = state.list_events(12)
            status_class = "ok" if health["status"] == "healthy" else "warn" if health["status"] == "warn" else "crit"
            body = [
                "<h1>finalis-mint dashboard</h1>",
                f"<p><span class='chip {status_class}'>{_html_escape(health['status'])}</span> reserve={health['available_reserve']} locked={health['wallet_locked_utxo_count']} paused={_html_escape(policy.get('redemptions_paused', False))}</p>",
                "<p><a href='/dashboard/incidents'>Incident view</a></p>",
                "<h2>Recent events</h2><table><tr><th>type</th><th>ack</th><th>created</th></tr>",
            ]
            for item in events:
                body.append(
                    f"<tr><td>{_html_escape(item.get('event_type',''))}</td><td>{_html_escape(item.get('acknowledged', False))}</td><td>{_html_escape(item.get('created_at',''))}</td></tr>"
                )
            body.append("</table><h2>Delivery queue</h2><table><tr><th>notifier</th><th>status</th><th>attempts</th><th>next</th></tr>")
            for job in jobs:
                body.append(
                    f"<tr><td>{_html_escape(job.get('notifier_id',''))}</td><td>{_html_escape(job.get('status',''))}</td><td>{_html_escape(job.get('attempts',''))}</td><td>{_html_escape(job.get('next_run_at',''))}</td></tr>"
                )
            body.append("</table>")
            return self._dashboard_html("finalis-mint dashboard", "".join(body))

        def _dashboard_incidents(self) -> str:
            data = self._incident_timeline_payload()
            dead_letters = data.get("dead_letters", [])
            silences = data.get("silences", [])
            body = [
                "<h1>Incident view</h1>",
                "<p><a href='/dashboard'>Back</a></p>",
                "<h2>Dead letters</h2><table><tr><th>event</th><th>notifier</th><th>error</th></tr>",
            ]
            for item in dead_letters:
                body.append(
                    f"<tr><td>{_html_escape(item.get('event_type',''))}</td><td>{_html_escape(item.get('notifier_id',''))}</td><td>{_html_escape(item.get('last_error',''))}</td></tr>"
                )
            body.append("</table><h2>Silences</h2><table><tr><th>type</th><th>until</th><th>reason</th></tr>")
            for item in silences:
                body.append(
                    f"<tr><td>{_html_escape(item.get('event_type',''))}</td><td>{_html_escape(item.get('until_ts',''))}</td><td>{_html_escape(item.get('reason',''))}</td></tr>"
                )
            body.append("</table>")
            return self._dashboard_html("finalis-mint incidents", "".join(body))

        def _incident_timeline_payload(self) -> dict[str, Any]:
            return {
                "generated_at": int(time.time()),
                "policy": state.policy(),
                "events": state.list_events(256),
                "silences": state.list_silences(False),
                "dead_letters": state.list_dead_letters(256),
                "notifiers": state.list_notifiers(),
            }

        def _replay_dead_letter(self, dead_letter_id: str) -> dict[str, Any]:
            removed = state.remove_dead_letter(dead_letter_id)
            event_id = str(removed.get("event_id", ""))
            notifier_id = str(removed.get("notifier_id", ""))
            event = next((item for item in state.list_events(256) if str(item.get("event_id", "")) == event_id), None)
            notifier = next((item for item in state.list_notifiers() if str(item.get("notifier_id", "")) == notifier_id), None)
            if not isinstance(event, dict) or not isinstance(notifier, dict):
                raise KeyError("replay target missing")
            state.update_event_delivery(event_id, notifier_id, "pending", 0, next_retry_at=0)
            event = next((item for item in state.list_events(256) if str(item.get("event_id", "")) == event_id), event)
            updated = self._deliver_event_to_notifier(notifier, event)
            self._record_event("dead_letter.replayed", {"dead_letter_id": dead_letter_id, "event_id": event_id, "notifier_id": notifier_id})
            return updated

        def _maybe_apply_auto_pause(self, summary: dict[str, Any], inventory: dict[str, Any], alerts: dict[str, Any]) -> dict[str, Any]:
            policy = state.policy()
            current = dict(policy)
            recommendation = self._policy_recommendations(summary, inventory, alerts)
            if not bool(policy.get("auto_pause_enabled", False)):
                return current
            if bool(policy.get("redemptions_paused", False)):
                return current
            if not bool(recommendation.get("auto_pause_recommended", False)):
                return current
            updated = state.update_policy(True, f"auto: {recommendation.get('auto_pause_reason', 'threshold triggered')}")
            self._record_event(
                "policy.auto_pause",
                {
                    "reason": updated.get("pause_reason", ""),
                    "available_reserve": int(summary.get("available_reserve", 0)),
                    "wallet_utxo_value": int(inventory.get("wallet_utxo_value", 0)),
                },
            )
            return updated

        def _remaining_utxos_after_selection(self, selected: list[dict[str, Any]]) -> list[dict[str, Any]]:
            selected_keys = {
                (str(item.get("txid", "")), int(item.get("vout", -1)))
                for item in selected
                if isinstance(item, dict)
            }
            remaining: list[dict[str, Any]] = []
            for item in self._reserve_raw_utxos():
                key = (str(item.get("txid", "")), int(item.get("vout", -1)))
                if key in self._locked_reserve_outpoints() or key in selected_keys:
                    continue
                remaining.append(item)
            return remaining

        def _inventory_metrics_from_values(self, values: list[int]) -> dict[str, Any]:
            ordered = sorted(values)
            return {
                "wallet_utxo_count": len(ordered),
                "wallet_utxo_value": sum(ordered),
                "wallet_fragment_smallest": ordered[0] if ordered else 0,
                "wallet_fragment_largest": ordered[-1] if ordered else 0,
                "wallet_fragment_below_min_change": sum(1 for value in ordered if value < RESERVE_MIN_CHANGE),
            }

        def _estimated_post_consolidation(self, selected: list[dict[str, Any]], output_value: int) -> dict[str, Any]:
            remaining = self._remaining_utxos_after_selection(selected)
            values = [int(item.get("value", 0)) for item in remaining if int(item.get("value", 0)) > 0]
            if output_value > 0:
                values.append(output_value)
            inventory = self._inventory_metrics_from_values(values)
            summary = dict(state.reserve_summary())
            summary.update({
                "available_reserve": int(summary.get("available_reserve", 0)),
                "reserve_balance": int(summary.get("reserve_balance", 0)),
            })
            alerts = self._reserve_alerts(summary, inventory)
            return {
                "wallet_utxo_count": inventory["wallet_utxo_count"],
                "wallet_utxo_value": inventory["wallet_utxo_value"],
                "wallet_fragment_smallest": inventory["wallet_fragment_smallest"],
                "wallet_fragment_largest": inventory["wallet_fragment_largest"],
                "wallet_fragment_below_min_change": inventory["wallet_fragment_below_min_change"],
                "alerts": {
                    "recommend_consolidation": bool(alerts.get("recommend_consolidation", False)),
                    "alert_fragmentation_threshold_breach": bool(alerts.get("alert_fragmentation_threshold_breach", False)),
                    "alert_max_inputs_pressure": bool(alerts.get("alert_max_inputs_pressure", False)),
                },
            }

        def _reserve_inventory(self) -> dict[str, Any]:
            if not config.lightserver_url or not config.reserve_address:
                return {
                    "wallet_utxo_count": 0,
                    "wallet_utxo_value": 0,
                    "wallet_locked_utxo_count": 0,
                    "wallet_locked_utxo_value": 0,
                    "wallet_fragment_smallest": 0,
                    "wallet_fragment_largest": 0,
                    "wallet_fragment_below_min_change": 0,
                    "wallet_synced_at": int(time.time()),
                }
            reserve_pkh = decode_finalis_address(config.reserve_address)
            if reserve_pkh is None:
                return {
                    "wallet_utxo_count": 0,
                    "wallet_utxo_value": 0,
                    "wallet_synced_at": int(time.time()),
                    "wallet_error": "invalid reserve address",
                }
            raw_utxos = self._reserve_raw_utxos()
            locked = self._locked_reserve_outpoints()
            utxos = [
                item for item in raw_utxos if (str(item.get("txid", "")), int(item.get("vout", -1))) not in locked
            ]
            values = sorted(int(item.get("value", 0)) for item in utxos)
            out = {
                "wallet_utxo_count": len(utxos),
                "wallet_utxo_value": sum(values),
                "wallet_locked_utxo_count": len(raw_utxos) - len(utxos),
                "wallet_locked_utxo_value": sum(int(item.get("value", 0)) for item in raw_utxos) - sum(values),
                "wallet_fragment_smallest": values[0] if values else 0,
                "wallet_fragment_largest": values[-1] if values else 0,
                "wallet_fragment_below_min_change": sum(1 for value in values if value < RESERVE_MIN_CHANGE),
                "wallet_synced_at": int(time.time()),
            }
            out.update(self._pending_network_spend_observation())
            return out

        def _select_reserve_utxos(self, amount_needed: int) -> list[dict[str, Any]]:
            reserve_pkh = decode_finalis_address(config.reserve_address)
            if reserve_pkh is None:
                raise ValueError("invalid reserve address")
            reserve_scripthash = hashlib.sha256(p2pkh_script_pubkey(reserve_pkh)).hexdigest()
            utxos = [
                item
                for item in lightserver_get_utxos(config.lightserver_url, reserve_scripthash)
                if int(item.get("value", 0)) > 0
                and (str(item.get("txid", "")), int(item.get("vout", -1))) not in self._locked_reserve_outpoints()
            ]
            utxos.sort(key=lambda item: int(item.get("value", 0)))
            selected: list[dict[str, Any]] = []
            total = 0
            for utxo in utxos:
                if len(selected) >= RESERVE_MAX_INPUTS:
                    break
                selected.append(utxo)
                total += int(utxo.get("value", 0))
                change = total - amount_needed
                if total == amount_needed or (total > amount_needed and change >= RESERVE_MIN_CHANGE):
                    return selected
            return []

        def _select_consolidation_utxos(self) -> list[dict[str, Any]]:
            reserve_pkh = decode_finalis_address(config.reserve_address)
            if reserve_pkh is None:
                raise ValueError("invalid reserve address")
            reserve_scripthash = hashlib.sha256(p2pkh_script_pubkey(reserve_pkh)).hexdigest()
            utxos = [
                item
                for item in lightserver_get_utxos(config.lightserver_url, reserve_scripthash)
                if int(item.get("value", 0)) > 0
                and (str(item.get("txid", "")), int(item.get("vout", -1))) not in self._locked_reserve_outpoints()
            ]
            if len(utxos) < 2:
                return []
            prioritized = sorted(
                utxos,
                key=lambda item: (
                    0 if int(item.get("value", 0)) < RESERVE_MIN_CHANGE else 1,
                    int(item.get("value", 0)),
                ),
            )
            if len(prioritized) < 2:
                return []
            if len(prioritized) < RESERVE_CONSOLIDATE_UTXO_COUNT and sum(
                1 for item in prioritized if int(item.get("value", 0)) < RESERVE_MIN_CHANGE
            ) == 0:
                return []
            return prioritized[:RESERVE_MAX_INPUTS]

        def _maybe_broadcast_redemption(self, batch_id: str) -> dict[str, Any]:
            redemption = state.get_redemption(batch_id)
            if not isinstance(redemption, dict):
                raise KeyError("unknown redemption_batch_id")
            if redemption.get("state") != "pending":
                return redemption
            if not config.lightserver_url or not config.reserve_privkey_hex or not config.reserve_address:
                return redemption
            selected = self._select_reserve_utxos(int(redemption["amount"]) + config.reserve_fee)
            if not selected:
                return redemption
            total_input_value = sum(int(item.get("value", 0)) for item in selected)
            amount_needed = int(redemption["amount"]) + config.reserve_fee
            change_value = total_input_value - amount_needed
            txid, tx_hex = build_redemption_tx(config, selected, str(redemption["redeem_address"]), int(redemption["amount"]))
            ok, err = lightserver_broadcast_tx(config.lightserver_url, tx_hex)
            if not ok:
                raise ValueError(err)
            return state.update_redemption(
                batch_id,
                "broadcast",
                txid,
                {
                    "selected_utxos": [
                        {
                            "txid": str(item["txid"]),
                            "vout": int(item["vout"]),
                            "value": int(item["value"]),
                        }
                        for item in selected
                    ],
                    "total_input_value": total_input_value,
                    "change_value": change_value,
                    "coin_selection_policy": "smallest-sufficient-non-dust-change",
                    "min_change": RESERVE_MIN_CHANGE,
                },
            )

        def _broadcast_consolidation(self) -> dict[str, Any]:
            if not config.lightserver_url or not config.reserve_privkey_hex or not config.reserve_address:
                raise ValueError("reserve wallet not configured")
            selected = self._select_consolidation_utxos()
            if len(selected) < 2:
                raise ValueError("no consolidation candidates available")
            total_input_value = _sum_utxo_values(selected)
            if total_input_value <= config.reserve_fee:
                raise ValueError("selected utxos do not cover reserve fee")
            txid, tx_hex = build_redemption_tx(
                config,
                selected,
                config.reserve_address,
                total_input_value - config.reserve_fee,
            )
            ok, err = lightserver_broadcast_tx(config.lightserver_url, tx_hex)
            if not ok:
                raise ValueError(err)
            consolidation_id = sha256_hex(
                [
                    "reserve-consolidation",
                    txid,
                    str(total_input_value),
                    str(len(selected)),
                ]
            )
            return state.record_consolidation(
                {
                    "consolidation_id": consolidation_id,
                    "state": "broadcast",
                    "l1_txid": txid,
                    "reserve_address": config.reserve_address,
                    "selected_utxos": [
                        {
                            "txid": str(item["txid"]),
                            "vout": int(item["vout"]),
                            "value": int(item["value"]),
                        }
                        for item in selected
                    ],
                    "total_input_value": total_input_value,
                    "output_value": total_input_value - config.reserve_fee,
                    "fee": config.reserve_fee,
                    "coin_selection_policy": "smallest-first-consolidation",
                    "max_inputs": RESERVE_MAX_INPUTS,
                }
            )

        def _consolidation_plan(self) -> dict[str, Any]:
            selected = self._select_consolidation_utxos()
            if len(selected) < 2:
                return {
                    "available": False,
                    "reason": "no consolidation candidates available",
                    "input_count": len(selected),
                }
            total_input_value = _sum_utxo_values(selected)
            if total_input_value <= config.reserve_fee:
                return {
                    "available": False,
                    "reason": "selected utxos do not cover reserve fee",
                    "input_count": len(selected),
                }
            return {
                "available": True,
                "coin_selection_policy": "smallest-first-consolidation",
                "input_count": len(selected),
                "total_input_value": total_input_value,
                "output_value": total_input_value - config.reserve_fee,
                "fee": config.reserve_fee,
                "estimated_post_action": self._estimated_post_consolidation(selected, total_input_value - config.reserve_fee),
                "selected_utxos": [
                    {
                        "txid": str(item["txid"]),
                        "vout": int(item["vout"]),
                        "value": int(item["value"]),
                    }
                    for item in selected
                ],
            }

        def do_GET(self) -> None:
            if self.path == "/healthz":
                write_json(self, HTTPStatus.OK, {"ok": True, "mint_id": config.mint_id})
                return
            if self.path == "/mint/key":
                write_json(
                    self,
                    HTTPStatus.OK,
                    {
                        "algorithm": "rsa-chaum-blind",
                        "modulus_hex": format(signer.n, "x"),
                        "public_exponent": signer.e,
                    },
                )
                return
            if self.path == "/operator/key":
                write_json(
                    self,
                    HTTPStatus.OK,
                    {
                        "algorithm": "rsa-sha256-raw",
                        "operator_key_id": primary_operator_key_id,
                        "modulus_hex": format(attestor.n, "x"),
                        "public_exponent": attestor.e,
                    },
                )
                return
            self._reconcile_all_broadcast()
            self._process_delivery_jobs()
            if self.path == "/dashboard":
                write_text(self, HTTPStatus.OK, self._dashboard_index(), "text/html; charset=utf-8")
                return
            if self.path == "/dashboard/incidents":
                write_text(self, HTTPStatus.OK, self._dashboard_incidents(), "text/html; charset=utf-8")
                return
            if self.path == "/reserves":
                summary = state.reserve_summary()
                summary["mint_id"] = config.mint_id
                summary["reserve_address"] = config.reserve_address
                inventory = self._reserve_inventory()
                alerts = self._reserve_alerts(summary, inventory)
                policy_state = self._maybe_apply_auto_pause(summary, inventory, alerts)
                if policy_state:
                    summary["policy_updated_at"] = policy_state.get("updated_at", 0)
                summary.update(inventory)
                summary.update(alerts)
                summary.update(self._policy_recommendations(summary, inventory, alerts))
                summary["reserve_health"] = self._reserve_health_summary(summary, inventory, alerts)
                write_json(self, HTTPStatus.OK, summary)
                return
            if self.path == "/monitoring/reserve_health":
                summary = state.reserve_summary()
                summary["mint_id"] = config.mint_id
                inventory = self._reserve_inventory()
                alerts = self._reserve_alerts(summary, inventory)
                self._maybe_apply_auto_pause(summary, inventory, alerts)
                write_json(self, HTTPStatus.OK, self._reserve_health_summary(summary, inventory, alerts))
                return
            if self.path == "/monitoring/worker":
                write_json(self, HTTPStatus.OK, self._worker_status())
                return
            if self.path == "/monitoring/metrics":
                summary = state.reserve_summary()
                inventory = self._reserve_inventory()
                alerts = self._reserve_alerts(summary, inventory)
                self._maybe_apply_auto_pause(summary, inventory, alerts)
                write_text(self, HTTPStatus.OK, self._metrics_payload(summary, inventory, alerts), "text/plain; version=0.0.4")
                return
            if self.path.startswith("/monitoring/alerts/history"):
                summary = state.reserve_summary()
                inventory = self._reserve_inventory()
                alerts = self._reserve_alerts(summary, inventory)
                self._maybe_apply_auto_pause(summary, inventory, alerts)
                write_json(self, HTTPStatus.OK, {"events": state.list_events(100), "silences": state.list_silences(False)})
                return
            if self.path == "/monitoring/events/policy":
                write_json(self, HTTPStatus.OK, state.policy())
                return
            if self.path == "/monitoring/events/silences":
                write_json(self, HTTPStatus.OK, {"silences": state.list_silences(False)})
                return
            if self.path == "/monitoring/notifiers":
                masked = []
                for item in state.list_notifiers():
                    row = dict(item)
                    row.pop("auth_token", None)
                    row.pop("auth_user", None)
                    row.pop("auth_pass", None)
                    masked.append(row)
                write_json(self, HTTPStatus.OK, {"notifiers": masked})
                return
            if self.path == "/monitoring/dead_letters":
                write_json(self, HTTPStatus.OK, {"dead_letters": state.list_dead_letters(100)})
                return
            if self.path == "/monitoring/incidents/export":
                payload = self._incident_timeline_payload()
                write_json(
                    self,
                    HTTPStatus.OK,
                    sign_snapshot(attestor, payload, primary_operator_key_id),
                )
                return
            if self.path == "/accounting/summary":
                summary = state.accounting_summary()
                summary["mint_id"] = config.mint_id
                write_json(self, HTTPStatus.OK, summary)
                return
            if self.path == "/attestations/reserves":
                inventory = self._reserve_inventory()
                payload = state.reserve_attestation(config.mint_id, inventory)
                alerts = self._reserve_alerts(payload, inventory)
                self._maybe_apply_auto_pause(payload, inventory, alerts)
                payload.update(alerts)
                payload.update(self._policy_recommendations(payload, inventory, alerts))
                payload["reserve_health"] = self._reserve_health_summary(payload, inventory, alerts)
                write_json(
                    self,
                    HTTPStatus.OK,
                    sign_snapshot(attestor, payload, primary_operator_key_id),
                )
                return
            if self.path == "/audit/export":
                if not self._require_operator(b""):
                    return
                inventory = self._reserve_inventory()
                payload = state.audit_export(config.mint_id, inventory)
                alerts = self._reserve_alerts(payload["reserves"], inventory)
                self._maybe_apply_auto_pause(payload["reserves"], inventory, alerts)
                payload["reserves"].update(alerts)
                payload["reserves"].update(self._policy_recommendations(payload["reserves"], inventory, alerts))
                payload["reserves"]["reserve_health"] = self._reserve_health_summary(payload["reserves"], inventory, alerts)
                write_json(
                    self,
                    HTTPStatus.OK,
                    sign_snapshot(attestor, payload, primary_operator_key_id),
                )
                return
            if self.path == "/reserves/consolidate_plan":
                if not self._require_operator(b""):
                    return
                write_json(self, HTTPStatus.OK, self._consolidation_plan())
                return
            if self.path == "/policy/redemptions":
                summary = state.reserve_summary()
                inventory = self._reserve_inventory()
                alerts = self._reserve_alerts(summary, inventory)
                self._maybe_apply_auto_pause(summary, inventory, alerts)
                policy = state.policy()
                policy.update(self._policy_recommendations(summary, inventory, alerts))
                policy["reserve_health"] = self._reserve_health_summary(summary, inventory, alerts)
                write_json(self, HTTPStatus.OK, policy)
                return
            write_json(self, HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_POST(self) -> None:
            length = self.headers.get("Content-Length")
            raw_body = b""
            if length:
                try:
                    raw_body = self.rfile.read(int(length))
                except Exception:
                    raw_body = b""
            try:
                body = json.loads(raw_body.decode("utf-8")) if raw_body else None
                if body is not None and not isinstance(body, dict):
                    body = None
            except Exception:
                body = None
            if body is None:
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid json body"})
                return

            if self.path == "/deposits/register":
                self._handle_deposit_register(body)
                return
            if self.path == "/issuance/blind":
                self._handle_blind_issue(body)
                return
            if self.path == "/redemptions/create":
                self._handle_redemption_create(body)
                return
            if self.path == "/redemptions/status":
                self._handle_redemption_status(body)
                return
            if self.path == "/redemptions/update":
                self._handle_redemption_update(body, raw_body)
                return
            if self.path == "/redemptions/approve_broadcast":
                self._handle_redemption_approve_broadcast(body, raw_body)
                return
            if self.path == "/reserves/consolidate":
                self._handle_reserve_consolidate(raw_body)
                return
            if self.path == "/policy/redemptions":
                self._handle_redemption_policy_update(body, raw_body)
                return
            if self.path == "/monitoring/events/ack":
                self._handle_event_ack(body, raw_body)
                return
            if self.path == "/monitoring/events/silence":
                self._handle_event_silence(body, raw_body)
                return
            if self.path == "/monitoring/events/policy":
                self._handle_event_policy_update(body, raw_body)
                return
            if self.path == "/monitoring/notifiers":
                self._handle_notifier_upsert(body, raw_body)
                return
            if self.path == "/monitoring/dead_letters/replay":
                self._handle_dead_letter_replay(body, raw_body)
                return

            write_json(self, HTTPStatus.NOT_FOUND, {"error": "not found"})

        def _handle_deposit_register(self, body: dict[str, Any]) -> None:
            required = ["chain", "deposit_txid", "deposit_vout", "mint_id", "recipient_pubkey_hash", "amount"]
            if any(k not in body for k in required):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "missing fields"})
                return
            if not is_hex_of_size(body["deposit_txid"], 32):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid deposit_txid"})
                return
            if not is_hex_of_size(body["mint_id"], 32):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid mint_id"})
                return
            if not is_hex_of_size(body["recipient_pubkey_hash"], 20):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid recipient_pubkey_hash"})
                return
            if config.mint_id and body["mint_id"].lower() != config.mint_id.lower():
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "mint_id mismatch"})
                return

            mint_deposit_ref = sha256_hex([
                str(body["chain"]),
                body["deposit_txid"],
                str(body["deposit_vout"]),
                body["mint_id"],
            ])
            deposit = {
                "chain": body["chain"],
                "deposit_txid": body["deposit_txid"],
                "deposit_vout": int(body["deposit_vout"]),
                "mint_id": body["mint_id"],
                "recipient_pubkey_hash": body["recipient_pubkey_hash"],
                "amount": int(body["amount"]),
                "mint_deposit_ref": mint_deposit_ref,
            }
            try:
                state.register_deposit(deposit)
            except ValueError as exc:
                write_json(self, HTTPStatus.CONFLICT, {"error": str(exc)})
                return
            write_json(
                self,
                HTTPStatus.OK,
                {
                    "accepted": True,
                    "finalization_depth_required": config.confirmations_required,
                    "confirmations_required": config.confirmations_required,
                    "mint_deposit_ref": mint_deposit_ref,
                },
            )

        def _handle_blind_issue(self, body: dict[str, Any]) -> None:
            mint_deposit_ref = body.get("mint_deposit_ref")
            blinded_messages = body.get("blinded_messages")
            note_amounts = body.get("note_amounts")
            if not isinstance(mint_deposit_ref, str) or not isinstance(blinded_messages, list) or not isinstance(note_amounts, list):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid fields"})
                return
            deposit = state.get_deposit(mint_deposit_ref)
            if deposit is None:
                write_json(self, HTTPStatus.NOT_FOUND, {"error": "unknown mint_deposit_ref"})
                return

            signed_blinds = []
            try:
                for msg in blinded_messages:
                    if not isinstance(msg, str) or not msg:
                        raise ValueError("blinded message must be a non-empty hex string")
                    signed_blinds.append(signer.sign_blinded_hex(msg))
                issuance = state.record_issuance(
                    mint_deposit_ref,
                    blinded_messages,
                    signed_blinds,
                    [int(v) for v in note_amounts],
                )
            except ValueError as exc:
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            except KeyError:
                write_json(self, HTTPStatus.NOT_FOUND, {"error": "unknown mint_deposit_ref"})
                return
            write_json(
                self,
                HTTPStatus.OK,
                {
                    "signed_blinds": signed_blinds,
                    "mint_epoch": 0,
                    "issuance_id": issuance["issuance_id"],
                    "note_refs": issuance["note_refs"],
                    "note_amounts": issuance["note_amounts"],
                },
            )

        def _handle_redemption_create(self, body: dict[str, Any]) -> None:
            notes = body.get("notes")
            redeem_address = body.get("redeem_address")
            amount = body.get("amount")
            if not isinstance(notes, list) or not isinstance(redeem_address, str) or not notes or not isinstance(amount, int):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid fields"})
                return
            if decode_finalis_address(redeem_address) is None:
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid redeem_address"})
                return
            if amount <= 0:
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "amount must be positive"})
                return
            for note in notes:
                if not isinstance(note, str):
                    write_json(self, HTTPStatus.BAD_REQUEST, {"error": "notes must be strings"})
                    return
                if state.note_already_spent(note):
                    write_json(self, HTTPStatus.CONFLICT, {"error": "note already spent"})
                    return

            batch_id = sha256_hex([redeem_address, *notes])
            redemption = {
                "redemption_batch_id": batch_id,
                "notes": list(notes),
                "redeem_address": redeem_address,
                "amount": amount,
                "state": "pending",
                "l1_txid": "",
            }
            try:
                state.create_redemption(redemption)
            except ValueError as exc:
                write_json(self, HTTPStatus.CONFLICT, {"error": str(exc)})
                return
            write_json(
                self,
                HTTPStatus.OK,
                {
                    "accepted": True,
                    "redemption_batch_id": batch_id,
                    "state": "pending",
                    "l1_txid": "",
                },
            )

        def _handle_redemption_status(self, body: dict[str, Any]) -> None:
            batch_id = body.get("redemption_batch_id")
            if not isinstance(batch_id, str):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid redemption_batch_id"})
                return
            self._reconcile_redemption(batch_id)
            redemption = state.get_redemption(batch_id)
            if redemption is None:
                write_json(self, HTTPStatus.NOT_FOUND, {"error": "unknown redemption_batch_id"})
                return
            observed = None
            if redemption["state"] == "broadcast" and redemption["l1_txid"]:
                observed = lightserver_finalization_depth(config.lightserver_url, redemption["l1_txid"])
            finalization_depth = observed[1] if observed is not None else 0
            write_json(
                self,
                HTTPStatus.OK,
                {
                    "state": redemption["state"],
                    "l1_txid": redemption["l1_txid"],
                    "amount": redemption["amount"],
                    "finalization_depth": finalization_depth,
                    "confirmations": finalization_depth,
                },
            )

        def _handle_redemption_update(self, body: dict[str, Any], raw_body: bytes) -> None:
            if not self._require_operator(raw_body):
                return
            batch_id = body.get("redemption_batch_id")
            new_state = body.get("state")
            l1_txid = body.get("l1_txid", "")
            if not isinstance(batch_id, str) or not isinstance(new_state, str):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid fields"})
                return
            if l1_txid and not is_hex_of_size(l1_txid, 32):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid l1_txid"})
                return
            if new_state == "broadcast":
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "broadcast state must use /redemptions/approve_broadcast"})
                return
            if new_state == "finalized":
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "finalized state is derived from lightserver observation"})
                return
            try:
                updated = state.update_redemption(batch_id, new_state, l1_txid)
            except KeyError:
                write_json(self, HTTPStatus.NOT_FOUND, {"error": "unknown redemption_batch_id"})
                return
            except ValueError as exc:
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            write_json(
                self,
                HTTPStatus.OK,
                {
                    "accepted": True,
                    "state": updated["state"],
                    "l1_txid": updated["l1_txid"],
                },
            )

        def _handle_redemption_approve_broadcast(self, body: dict[str, Any], raw_body: bytes) -> None:
            if not self._require_operator(raw_body):
                return
            batch_id = body.get("redemption_batch_id")
            if not isinstance(batch_id, str) or not batch_id:
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid redemption_batch_id"})
                return
            try:
                updated = self._maybe_broadcast_redemption(batch_id)
            except KeyError:
                write_json(self, HTTPStatus.NOT_FOUND, {"error": "unknown redemption_batch_id"})
                return
            except (ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            write_json(
                self,
                HTTPStatus.OK,
                {
                    "accepted": True,
                    "state": updated["state"],
                    "l1_txid": updated.get("l1_txid", ""),
                },
            )

        def _handle_reserve_consolidate(self, raw_body: bytes) -> None:
            if not self._require_operator(raw_body):
                return
            try:
                item = self._broadcast_consolidation()
            except (ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            write_json(
                self,
                HTTPStatus.OK,
                {
                    "accepted": True,
                    "consolidation_id": item["consolidation_id"],
                    "state": item["state"],
                    "l1_txid": item["l1_txid"],
                    "input_count": len(item.get("selected_utxos", [])),
                    "total_input_value": item["total_input_value"],
                    "output_value": item["output_value"],
                    "fee": item["fee"],
                },
            )

        def _handle_redemption_policy_update(self, body: dict[str, Any], raw_body: bytes) -> None:
            if not self._require_operator(raw_body):
                return
            paused = body.get("redemptions_paused")
            reason = body.get("pause_reason", "")
            auto_pause_enabled = body.get("auto_pause_enabled")
            event_retention_limit = body.get("event_retention_limit")
            export_include_acknowledged = body.get("export_include_acknowledged")
            if not isinstance(paused, bool) or not isinstance(reason, str):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid policy fields"})
                return
            if auto_pause_enabled is not None and not isinstance(auto_pause_enabled, bool):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid auto_pause_enabled"})
                return
            if event_retention_limit is not None and not isinstance(event_retention_limit, int):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid event_retention_limit"})
                return
            if export_include_acknowledged is not None and not isinstance(export_include_acknowledged, bool):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid export_include_acknowledged"})
                return
            policy = state.update_policy(
                paused,
                reason,
                auto_pause_enabled,
                event_retention_limit,
                export_include_acknowledged,
            )
            self._record_event(
                "policy.operator_update",
                {
                    "redemptions_paused": bool(policy.get("redemptions_paused", False)),
                    "pause_reason": str(policy.get("pause_reason", "")),
                    "auto_pause_enabled": bool(policy.get("auto_pause_enabled", False)),
                    "event_retention_limit": int(policy.get("event_retention_limit", 256)),
                    "export_include_acknowledged": bool(policy.get("export_include_acknowledged", True)),
                },
            )
            summary = state.reserve_summary()
            inventory = self._reserve_inventory()
            alerts = self._reserve_alerts(summary, inventory)
            policy.update(self._policy_recommendations(summary, inventory, alerts))
            policy["reserve_health"] = self._reserve_health_summary(summary, inventory, alerts)
            write_json(self, HTTPStatus.OK, {"accepted": True, **policy})

        def _handle_event_ack(self, body: dict[str, Any], raw_body: bytes) -> None:
            if not self._require_operator(raw_body):
                return
            event_id = body.get("event_id")
            note = body.get("note", "")
            if not isinstance(event_id, str) or not isinstance(note, str) or not event_id:
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid event ack fields"})
                return
            try:
                updated = state.acknowledge_event(event_id, note)
            except KeyError:
                write_json(self, HTTPStatus.NOT_FOUND, {"error": "unknown event_id"})
                return
            self._record_event("event.acknowledged", {"event_id": event_id, "note": note})
            write_json(self, HTTPStatus.OK, {"accepted": True, "event": updated})

        def _handle_event_silence(self, body: dict[str, Any], raw_body: bytes) -> None:
            if not self._require_operator(raw_body):
                return
            event_type = body.get("event_type")
            until_ts = body.get("until_ts")
            reason = body.get("reason", "")
            if not isinstance(event_type, str) or not isinstance(until_ts, int) or not isinstance(reason, str) or not event_type:
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid silence fields"})
                return
            silence = state.add_silence(event_type, until_ts, reason)
            self._record_event("event.silenced", {"event_type": event_type, "until_ts": until_ts, "reason": reason})
            write_json(self, HTTPStatus.OK, {"accepted": True, "silence": silence})

        def _handle_event_policy_update(self, body: dict[str, Any], raw_body: bytes) -> None:
            if not self._require_operator(raw_body):
                return
            retention = body.get("event_retention_limit")
            export_include_acknowledged = body.get("export_include_acknowledged")
            if retention is not None and not isinstance(retention, int):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid event_retention_limit"})
                return
            if export_include_acknowledged is not None and not isinstance(export_include_acknowledged, bool):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid export_include_acknowledged"})
                return
            current = state.policy()
            updated = state.update_policy(
                bool(current.get("redemptions_paused", False)),
                str(current.get("pause_reason", "")),
                bool(current.get("auto_pause_enabled", False)),
                retention,
                export_include_acknowledged,
            )
            self._record_event(
                "event.policy_update",
                {
                    "event_retention_limit": int(updated.get("event_retention_limit", 256)),
                    "export_include_acknowledged": bool(updated.get("export_include_acknowledged", True)),
                },
            )
            write_json(self, HTTPStatus.OK, {"accepted": True, **updated})

        def _handle_notifier_upsert(self, body: dict[str, Any], raw_body: bytes) -> None:
            if not self._require_operator(raw_body):
                return
            notifier_id = body.get("notifier_id")
            kind = body.get("kind")
            target = body.get("target")
            enabled = body.get("enabled", True)
            retry_max_attempts = body.get("retry_max_attempts", 3)
            retry_backoff_seconds = body.get("retry_backoff_seconds", 30)
            auth_type = body.get("auth_type", "none")
            auth_token_secret_ref = body.get("auth_token_secret_ref", "")
            auth_user_secret_ref = body.get("auth_user_secret_ref", "")
            auth_pass_secret_ref = body.get("auth_pass_secret_ref", "")
            tls_verify = body.get("tls_verify", True)
            tls_ca_file = body.get("tls_ca_file", "")
            tls_client_cert_file = body.get("tls_client_cert_file", "")
            tls_client_key_file = body.get("tls_client_key_file", "")
            if not isinstance(notifier_id, str) or not isinstance(kind, str) or not isinstance(target, str) or not isinstance(enabled, bool):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid notifier fields"})
                return
            if not isinstance(retry_max_attempts, int) or not isinstance(retry_backoff_seconds, int):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid notifier retry fields"})
                return
            if not isinstance(auth_type, str) or auth_type not in {"none", "bearer", "basic"}:
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid notifier auth_type"})
                return
            if not isinstance(tls_verify, bool) or not isinstance(tls_ca_file, str):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid notifier tls fields"})
                return
            if not isinstance(auth_token_secret_ref, str) or not isinstance(auth_user_secret_ref, str) or not isinstance(auth_pass_secret_ref, str):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid notifier secret refs"})
                return
            if not isinstance(tls_client_cert_file, str) or not isinstance(tls_client_key_file, str):
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid notifier client tls fields"})
                return
            if kind not in {"webhook", "alertmanager", "email_spool"}:
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "unsupported notifier kind"})
                return
            notifier = {
                "notifier_id": notifier_id,
                "kind": kind,
                "target": target,
                "enabled": enabled,
                "retry_max_attempts": max(1, retry_max_attempts),
                "retry_backoff_seconds": max(1, retry_backoff_seconds),
                "auth_type": auth_type,
                "auth_token_secret_ref": str(auth_token_secret_ref),
                "auth_user_secret_ref": str(auth_user_secret_ref),
                "auth_pass_secret_ref": str(auth_pass_secret_ref),
                "tls_verify": tls_verify,
                "tls_ca_file": tls_ca_file,
                "tls_client_cert_file": tls_client_cert_file,
                "tls_client_key_file": tls_client_key_file,
            }
            if kind == "email_spool":
                notifier["email_to"] = str(body.get("email_to", "ops@example.invalid"))
                notifier["email_from"] = str(body.get("email_from", "finalis-mint@example.invalid"))
            saved = state.upsert_notifier(notifier)
            self._record_event("notifier.upsert", {"notifier_id": notifier_id, "kind": kind, "enabled": enabled})
            write_json(self, HTTPStatus.OK, {"accepted": True, "notifier": saved})

        def _handle_dead_letter_replay(self, body: dict[str, Any], raw_body: bytes) -> None:
            if not self._require_operator(raw_body):
                return
            dead_letter_id = body.get("dead_letter_id")
            if not isinstance(dead_letter_id, str) or not dead_letter_id:
                write_json(self, HTTPStatus.BAD_REQUEST, {"error": "invalid dead_letter_id"})
                return
            try:
                event = self._replay_dead_letter(dead_letter_id)
            except KeyError:
                write_json(self, HTTPStatus.NOT_FOUND, {"error": "unknown dead_letter_id"})
                return
            write_json(self, HTTPStatus.OK, {"accepted": True, "event": event})

    return MintHandler


def emit_worker_lease_events(handler: Any, state: MintState, acquire_info: dict[str, Any], mode: str, seen_takeover: set[str]) -> None:
    if not bool(acquire_info.get("acquired", False)):
        return
    stale_owner = str(acquire_info.get("stale_owner_pid", ""))
    if bool(acquire_info.get("takeover", False)):
        key = f"{mode}:{stale_owner}"
        if key in seen_takeover:
            return
        seen_takeover.add(key)
        handler._record_event(  # type: ignore[attr-defined]
            "worker.lease_takeover",
            {
                "mode": mode,
                "stale_owner_pid": stale_owner,
                "lock_file": handler._worker_status().get("lock_file", ""),  # type: ignore[attr-defined]
                "takeover_policy": "allow-after-stale-timeout",
            },
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Minimal finalis-mint boundary service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--state-file", default="/tmp/finalis-mint-state.json")
    parser.add_argument(
        "--confirmations-required",
        type=int,
        default=1,
        help="Legacy compatibility alias for required finalized-depth threshold.",
    )
    parser.add_argument(
        "--signing-seed",
        default="finalis-mint-dev-seed",
        help="Deterministic placeholder seed for blind issuance responses.",
    )
    parser.add_argument(
        "--mint-id",
        default="",
        help="Optional 32-byte hex mint id to enforce on /deposits/register.",
    )
    parser.add_argument(
        "--operator-key",
        action="append",
        default=[],
        help="Operator auth key in key_id:hex_secret form. May be repeated.",
    )
    parser.add_argument(
        "--lightserver-url",
        default="",
        help="Optional lightserver RPC URL used to reconcile redemption tx finalization depth.",
    )
    parser.add_argument("--reserve-privkey", default="", help="Hex-encoded reserve wallet private key for redemption settlement.")
    parser.add_argument("--reserve-address", default="", help="Reserve wallet address used for change and UTXO discovery.")
    parser.add_argument("--reserve-fee", type=int, default=1000, help="L1 fee used for redemption settlement transactions.")
    parser.add_argument("--cli-path", default="./build/finalis-cli", help="Path to finalis-cli used for tx construction.")
    parser.add_argument("--notifier-retry-interval-seconds", type=int, default=5, help="Background notifier retry interval.")
    parser.add_argument("--notifier-secrets-file", default="", help="Optional JSON file mapping notifier secret refs to secret values.")
    parser.add_argument("--notifier-secret-dir", default="", help="Optional directory containing notifier secrets as individual files keyed by secret ref.")
    parser.add_argument("--notifier-secret-env-prefix", default="FINALIS_MINT_SECRET_", help="Optional env prefix used for notifier secret refs.")
    parser.add_argument("--notifier-secret-backend", choices=["auto", "dir", "env", "json", "command"], default="auto", help="Secret backend used to resolve notifier secret refs.")
    parser.add_argument("--notifier-secret-helper-cmd", default="", help="Optional helper command used when --notifier-secret-backend=command. The ref is appended as the last arg.")
    parser.add_argument("--worker-lock-file", default="", help="Optional file lock used to ensure only one process drains delivery jobs.")
    parser.add_argument("--worker-stale-timeout-seconds", type=int, default=30, help="Worker lease timeout before takeover is allowed.")
    parser.add_argument("--mode", choices=["server", "worker", "all"], default="server", help="Run HTTP server, worker loop, or both.")
    args = parser.parse_args()

    operator_keys = parse_operator_keys(args.operator_key)
    primary_operator_key_id = next(iter(operator_keys))

    config = MintConfig(
        state_file=Path(args.state_file),
        confirmations_required=args.confirmations_required,
        signing_seed=args.signing_seed,
        mint_id=args.mint_id,
        operator_keys=operator_keys,
        lightserver_url=args.lightserver_url,
        reserve_privkey_hex=args.reserve_privkey,
        reserve_address=args.reserve_address,
        reserve_fee=args.reserve_fee,
        cli_path=args.cli_path,
        notifier_retry_interval_seconds=max(1, args.notifier_retry_interval_seconds),
        notifier_secrets_file=Path(args.notifier_secrets_file) if args.notifier_secrets_file else None,
        notifier_secret_dir=Path(args.notifier_secret_dir) if args.notifier_secret_dir else None,
        notifier_secret_env_prefix=str(args.notifier_secret_env_prefix),
        notifier_secret_backend=str(args.notifier_secret_backend),
        notifier_secret_helper_cmd=str(args.notifier_secret_helper_cmd),
        worker_lock_file=Path(args.worker_lock_file) if args.worker_lock_file else None,
        worker_stale_timeout_seconds=max(5, int(args.worker_stale_timeout_seconds)),
    )
    state = MintState(config.state_file)
    signer = BlindSigner.from_seed(config.signing_seed)
    attestor = BlindSigner.from_seed(config.signing_seed + ":attestation")
    leader_lock = WorkerLeaderLock(config.worker_lock_file, config.worker_stale_timeout_seconds)
    handler_cls = make_handler(config, state, signer, attestor, primary_operator_key_id, leader_lock)

    seen_takeover: set[str] = set()

    if args.mode == "worker":
        retry_handler = handler_cls.__new__(handler_cls)
        print("finalis-mint worker started", flush=True)
        try:
            while True:
                acquire_info = leader_lock.acquire_status("worker")
                if acquire_info.get("acquired", False):
                    emit_worker_lease_events(retry_handler, state, acquire_info, "worker", seen_takeover)
                    retry_handler._process_delivery_jobs()  # type: ignore[attr-defined]
                    leader_lock.heartbeat()
                time.sleep(config.notifier_retry_interval_seconds)
        except KeyboardInterrupt:
            pass
        finally:
            leader_lock.release()
        return 0

    server = ThreadingHTTPServer((args.host, args.port), handler_cls)
    stop_retry = threading.Event()
    retry_thread: threading.Thread | None = None

    if args.mode == "all":
        def retry_loop() -> None:
            retry_handler = handler_cls.__new__(handler_cls)
            while not stop_retry.wait(config.notifier_retry_interval_seconds):
                try:
                    acquire_info = leader_lock.acquire_status("all")
                    if acquire_info.get("acquired", False):
                        emit_worker_lease_events(retry_handler, state, acquire_info, "all", seen_takeover)
                        retry_handler._process_delivery_jobs()  # type: ignore[attr-defined]
                        leader_lock.heartbeat()
                except Exception:
                    continue

        retry_thread = threading.Thread(target=retry_loop, daemon=True)
        retry_thread.start()

    print(f"finalis-mint listening on http://{args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_retry.set()
        server.server_close()
        if retry_thread is not None:
            retry_thread.join(timeout=5)
        leader_lock.release()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
