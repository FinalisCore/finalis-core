# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import math
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER = REPO_ROOT / "services" / "finalis-mint" / "server.py"
CLI = REPO_ROOT / "build" / "finalis-cli"


def free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def http_get_json(url: str, headers: dict[str, str] | None = None) -> dict:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def http_post_json(url: str, payload: dict, headers: dict[str, str] | None = None) -> tuple[int, dict]:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def load_server_module():
    import importlib.util
    import sys

    spec = importlib.util.spec_from_file_location("finalis_mint_server_integration", SERVER)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load server module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


server_module = load_server_module()


class FakeLightserver:
    def __init__(self, port: int) -> None:
        self.port = port
        self.tip_height = 0
        self.tx_heights: dict[str, int] = {}
        self.utxos_by_scripthash: dict[str, list[dict]] = {}
        self.broadcast_spend_queue: list[list[tuple[str, int]]] = []
        self._server = ThreadingHTTPServer(("127.0.0.1", port), self._make_handler())
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def _make_handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                body = json.loads(raw.decode("utf-8"))
                method = body.get("method")
                req_id = body.get("id")
                params = body.get("params")
                if not isinstance(params, dict):
                    params = {}
                if method == "get_status":
                    payload = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"height": outer.tip_height},
                    }
                    self._write_json(HTTPStatus.OK, payload)
                    return
                if method == "get_tx_status":
                    txid = params.get("txid", "")
                    if txid not in outer.tx_heights:
                        payload = {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "txid": txid,
                                "status": "not_found",
                                "finalized": False,
                                "finalized_depth": 0,
                                "credit_safe": False,
                            },
                        }
                    else:
                        height = int(outer.tx_heights[txid])
                        finalized_depth = max(0, outer.tip_height - height + 1)
                        payload = {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "txid": txid,
                                "status": "finalized",
                                "finalized": True,
                                "height": height,
                                "finalized_depth": finalized_depth,
                                "credit_safe": finalized_depth > 0,
                            },
                        }
                    self._write_json(HTTPStatus.OK, payload)
                    return
                if method == "get_tx":
                    txid = params.get("txid", "")
                    if txid not in outer.tx_heights:
                        payload = {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "error": {"code": -32001, "message": "not found"},
                        }
                    else:
                        payload = {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {"height": outer.tx_heights[txid], "tx_hex": ""},
                        }
                    self._write_json(HTTPStatus.OK, payload)
                    return
                if method == "get_utxos":
                    sh = params.get("scripthash_hex", "")
                    payload = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": outer.utxos_by_scripthash.get(sh, []),
                    }
                    self._write_json(HTTPStatus.OK, payload)
                    return
                if method == "broadcast_tx":
                    tx_hex = params.get("tx_hex", "")
                    if outer.broadcast_spend_queue:
                        spent = set(outer.broadcast_spend_queue.pop(0))
                        updated: dict[str, list[dict]] = {}
                        for scripthash, utxos in outer.utxos_by_scripthash.items():
                            updated[scripthash] = [
                                item
                                for item in utxos
                                if (str(item.get("txid", "")), int(item.get("vout", -1))) not in spent
                            ]
                        outer.utxos_by_scripthash = updated
                    payload = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"accepted": True, "txid": tx_hex[:64] if isinstance(tx_hex, str) else ""},
                    }
                    self._write_json(HTTPStatus.OK, payload)
                    return
                self._write_json(
                    HTTPStatus.OK,
                    {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "method not found"}},
                )

            def _write_json(self, status: HTTPStatus, payload: dict) -> None:
                data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        return Handler

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


class FakeNotifierSink:
    def __init__(self, port: int) -> None:
        self.port = port
        self.received: list[dict] = []
        self._server = ThreadingHTTPServer(("127.0.0.1", port), self._make_handler())
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def _make_handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args) -> None:
                return

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                payload = json.loads(raw.decode("utf-8"))
                outer.received.append(
                    {
                        "path": self.path,
                        "payload": payload,
                        "authorization": self.headers.get("Authorization", ""),
                    }
                )
                if self.path == "/fail":
                    self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"{}")
                    return
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

        return Handler

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


class MintIntegrationTests(unittest.TestCase):
    def test_lightserver_helpers_use_live_params_contract(self) -> None:
        port = free_port()
        lightserver = FakeLightserver(port)
        lightserver.tip_height = 12
        txid = "aa" * 32
        scripthash = "bb" * 32
        lightserver.tx_heights[txid] = 9
        lightserver.utxos_by_scripthash[scripthash] = [{"txid": "cc" * 32, "vout": 1, "value": 1234}]
        lightserver.start()
        try:
            url = f"http://127.0.0.1:{port}/rpc"
            self.assertEqual(server_module.lightserver_finalization_depth(url, txid), (9, 4))
            self.assertEqual(server_module.lightserver_get_utxos(url, scripthash), lightserver.utxos_by_scripthash[scripthash])
            ok, returned_txid = server_module.lightserver_broadcast_tx(url, "dd" * 64)
            self.assertTrue(ok)
            self.assertEqual(returned_txid, "dd" * 32)
        finally:
            lightserver.stop()

    def test_worker_stale_lease_takeover_emits_event(self) -> None:
        port = free_port()
        lightserver_port = free_port()
        notifier_port = free_port()
        lightserver = FakeLightserver(lightserver_port)
        notifier = FakeNotifierSink(notifier_port)
        lightserver.start()
        notifier.start()
        operator_key_id = "integration-operator"
        operator_secret_hex = "11" * 32
        try:
            with tempfile.TemporaryDirectory() as td:
                state_path = Path(td) / "mint-state.json"
                lock_path = Path(td) / "worker.lock"
                email_spool = Path(td) / "email-spool"
                state_path.write_text(
                    json.dumps(
                        {
                            "notifiers": [
                                {
                                    "notifier_id": "ops-takeover",
                                    "kind": "webhook",
                                    "target": f"http://127.0.0.1:{notifier_port}/webhook",
                                    "enabled": True,
                                    "retry_max_attempts": 2,
                                    "retry_backoff_seconds": 1,
                                    "auth_type": "none",
                                    "tls_verify": True,
                                    "tls_ca_file": "",
                                    "tls_client_cert_file": "",
                                    "tls_client_key_file": "",
                                },
                                {
                                    "notifier_id": "ops-takeover-alertmanager",
                                    "kind": "alertmanager",
                                    "target": f"http://127.0.0.1:{notifier_port}/alertmanager",
                                    "enabled": True,
                                    "retry_max_attempts": 2,
                                    "retry_backoff_seconds": 1,
                                    "auth_type": "none",
                                    "tls_verify": True,
                                    "tls_ca_file": "",
                                    "tls_client_cert_file": "",
                                    "tls_client_key_file": "",
                                },
                                {
                                    "notifier_id": "ops-takeover-email",
                                    "kind": "email_spool",
                                    "target": str(email_spool),
                                    "enabled": True,
                                    "retry_max_attempts": 2,
                                    "retry_backoff_seconds": 1,
                                    "auth_type": "none",
                                    "tls_verify": True,
                                    "tls_ca_file": "",
                                    "tls_client_cert_file": "",
                                    "tls_client_key_file": "",
                                    "email_to": "ops@example.test",
                                    "email_from": "mint@example.test",
                                }
                            ]
                        }
                    ),
                    encoding="utf-8",
                )
                stale_state = {
                    "owner_pid": 424242,
                    "heartbeat_at": 1,
                    "acquired_at": 1,
                    "mode": "worker",
                    "stale_timeout_seconds": 5,
                }
                lock_path.write_text(json.dumps(stale_state), encoding="utf-8")
                common_args = [
                    "python3",
                    str(SERVER),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--state-file",
                    str(state_path),
                    "--mint-id",
                    "22" * 32,
                    "--signing-seed",
                    "integration-seed",
                    "--operator-key",
                    f"{operator_key_id}:{operator_secret_hex}",
                    "--lightserver-url",
                    f"http://127.0.0.1:{lightserver_port}/rpc",
                    "--worker-lock-file",
                    str(lock_path),
                    "--worker-stale-timeout-seconds",
                    "5",
                    "--notifier-retry-interval-seconds",
                    "1",
                ]
                proc = subprocess.Popen(
                    common_args + ["--mode", "server"],
                    cwd=REPO_ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                worker_proc = subprocess.Popen(
                    common_args + ["--mode", "worker"],
                    cwd=REPO_ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                try:
                    for _ in range(50):
                        try:
                            health = http_get_json(f"http://127.0.0.1:{port}/healthz")
                            if health.get("ok"):
                                break
                        except Exception:
                            time.sleep(0.1)
                    else:
                        self.fail("mint service did not become ready")

                    takeover_event = None
                    for _ in range(40):
                        history = http_get_json(f"http://127.0.0.1:{port}/monitoring/alerts/history")
                        takeover_event = next((item for item in history["events"] if item["event_type"] == "worker.lease_takeover"), None)
                        if takeover_event is not None:
                            break
                        time.sleep(0.1)
                    if takeover_event is None:
                        raw_state = json.loads(state_path.read_text(encoding="utf-8"))
                        events = raw_state.get("events", [])
                        takeover_event = next((item for item in events if item.get("event_type") == "worker.lease_takeover"), None)
                    self.assertIsNotNone(takeover_event)
                    self.assertEqual(takeover_event["payload"]["stale_owner_pid"], "424242")
                    for _ in range(20):
                        paths = {item["path"] for item in notifier.received}
                        if "/webhook" in paths and "/alertmanager" in paths and len(list(email_spool.glob("*.eml"))) >= 1:
                            break
                        time.sleep(0.1)
                    self.assertIn("/webhook", {item["path"] for item in notifier.received})
                    self.assertIn("/alertmanager", {item["path"] for item in notifier.received})
                    self.assertGreaterEqual(len(list(email_spool.glob("*.eml"))), 1)

                    worker_status = http_get_json(f"http://127.0.0.1:{port}/monitoring/worker")
                    self.assertEqual(worker_status["takeover_policy"], "allow-after-stale-timeout")
                    self.assertFalse(worker_status["stale"])
                    self.assertNotEqual(worker_status["owner_pid"], "424242")
                finally:
                    worker_proc.terminate()
                    try:
                        worker_proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        worker_proc.kill()
                        worker_proc.wait(timeout=5)
                    if worker_proc.stdout is not None:
                        worker_proc.stdout.close()
                    if worker_proc.stderr is not None:
                        worker_proc.stderr.close()
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
                    if proc.stdout is not None:
                        proc.stdout.close()
                    if proc.stderr is not None:
                        proc.stderr.close()
        finally:
            lightserver.stop()
            notifier.stop()

    def test_cli_roundtrip_against_live_service(self) -> None:
        port = free_port()
        lightserver_port = free_port()
        notifier_port = free_port()
        lightserver = FakeLightserver(lightserver_port)
        notifier = FakeNotifierSink(notifier_port)
        lightserver.start()
        notifier.start()
        operator_key_id = "integration-operator"
        operator_secret_hex = "11" * 32
        try:
            with tempfile.TemporaryDirectory() as td:
                state_path = Path(td) / "mint-state.json"
                secrets_path = Path(td) / "notifier-secrets.json"
                lock_path = Path(td) / "worker.lock"
                email_spool = Path(td) / "email-spool"
                reserve_wallet = Path(td) / "reserve-wallet.json"
                secrets_path.write_text(json.dumps({"ops_webhook_bearer": "integration-token"}), encoding="utf-8")
                reserve_privkey = "55" * 32
                wallet_cmd = [
                    str(CLI),
                    "wallet_import",
                    "--out",
                    str(reserve_wallet),
                    "--privkey",
                    reserve_privkey,
                ]
                wallet = subprocess.run(wallet_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                wallet_lines = dict(line.split("=", 1) for line in wallet.stdout.strip().splitlines())
                reserve_address = wallet_lines["address"]

                address_cmd = [
                    str(CLI),
                    "wallet_export",
                    "--file",
                    str(reserve_wallet),
                ]
                exported = subprocess.run(address_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                exported_lines = dict(line.split("=", 1) for line in exported.stdout.strip().splitlines())
                reserve_pubkey = exported_lines["pubkey_hex"]
                reserve_pkh_cmd = [
                    str(CLI),
                    "address_from_pubkey",
                    "--pubkey",
                    reserve_pubkey,
                ]
                reserve_addr_check = subprocess.run(reserve_pkh_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                self.assertEqual(reserve_addr_check.stdout.strip(), reserve_address)
                reserve_scripthash = "0000000000000000000000000000000000000000000000000000000000000000"
                utxo_txid_a = "66" * 32
                utxo_txid_b = "77" * 32
                # P2PKH script hash: sha256(76a914 || pkh || 88ac)
                reserve_pkh = server_module.decode_finalis_address(reserve_address)
                self.assertIsNotNone(reserve_pkh)
                reserve_scripthash = __import__("hashlib").sha256(server_module.p2pkh_script_pubkey(reserve_pkh)).hexdigest()
                lightserver.utxos_by_scripthash[reserve_scripthash] = [
                    {
                        "txid": utxo_txid_a,
                        "vout": 0,
                        "value": 60000,
                        "height": 1,
                        "script_pubkey_hex": "",
                    },
                    {
                        "txid": utxo_txid_b,
                        "vout": 1,
                        "value": 50000,
                        "height": 1,
                        "script_pubkey_hex": "",
                    }
                ]
                common_args = [
                    "python3",
                    str(SERVER),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--state-file",
                    str(state_path),
                    "--mint-id",
                    "22" * 32,
                    "--signing-seed",
                    "integration-seed",
                    "--operator-key",
                    f"{operator_key_id}:{operator_secret_hex}",
                    "--lightserver-url",
                    f"http://127.0.0.1:{lightserver_port}/rpc",
                    "--reserve-privkey",
                    reserve_privkey,
                    "--reserve-address",
                    reserve_address,
                    "--cli-path",
                    str(CLI),
                    "--notifier-retry-interval-seconds",
                    "1",
                    "--notifier-secrets-file",
                    str(secrets_path),
                    "--worker-lock-file",
                    str(lock_path),
                ]
                proc = subprocess.Popen(
                    common_args + [
                        "--mode",
                        "server",
                    ],
                    cwd=REPO_ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                worker_proc = subprocess.Popen(
                    common_args + [
                        "--mode",
                        "worker",
                    ],
                    cwd=REPO_ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                try:
                    for _ in range(50):
                        try:
                            health = http_get_json(f"http://127.0.0.1:{port}/healthz")
                            if health.get("ok"):
                                break
                        except Exception:
                            time.sleep(0.1)
                    else:
                        self.fail("mint service did not become ready")

                    worker_status = http_get_json(f"http://127.0.0.1:{port}/monitoring/worker")
                    self.assertEqual(worker_status["lock_file"], str(lock_path))
                    self.assertIn("owner_pid", worker_status)
                    # Some environments may not expose a lock owner pid even when the lock is held.
                    self.assertIsNotNone(worker_status["owner_pid"])
                    self.assertEqual(worker_status["takeover_policy"], "allow-after-stale-timeout")

                    deposit_cmd = [
                        str(CLI),
                        "mint_deposit_register",
                        "--url",
                        f"http://127.0.0.1:{port}/deposits/register",
                        "--deposit-txid",
                        "11" * 32,
                        "--deposit-vout",
                        "0",
                        "--mint-id",
                        "22" * 32,
                        "--recipient-address",
                        "sc1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaczjbkjy",
                        "--amount",
                        "100000",
                    ]
                    dep = subprocess.run(deposit_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    lines = dict(line.split("=", 1) for line in dep.stdout.strip().splitlines())
                    mint_deposit_ref = lines["mint_deposit_ref"]

                    policy_before = http_get_json(f"http://127.0.0.1:{port}/policy/redemptions")
                    self.assertFalse(policy_before.get("redemptions_paused", False))
                    self.assertFalse(policy_before.get("auto_pause_recommended", False))
                    self.assertEqual(policy_before["reserve_health"]["status"], "healthy")

                    pause_cmd = [
                        str(CLI),
                        "mint_redemptions_pause",
                        "--url",
                        f"http://127.0.0.1:{port}/policy/redemptions",
                        "--operator-key-id",
                        operator_key_id,
                        "--operator-secret-hex",
                        operator_secret_hex,
                        "--reason",
                        "reserve low",
                    ]
                    paused = subprocess.run(pause_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    paused_json = json.loads(paused.stdout)
                    self.assertTrue(paused_json["redemptions_paused"])

                    blocked_status, blocked_body = http_post_json(
                        f"http://127.0.0.1:{port}/redemptions/create",
                        {
                            "notes": ["note-blocked"],
                            "redeem_address": reserve_address,
                            "amount": 1000,
                        },
                    )
                    self.assertEqual(blocked_status, HTTPStatus.CONFLICT)
                    self.assertIn("redemptions paused", blocked_body["error"])

                    resume_cmd = [
                        str(CLI),
                        "mint_redemptions_resume",
                        "--url",
                        f"http://127.0.0.1:{port}/policy/redemptions",
                        "--operator-key-id",
                        operator_key_id,
                        "--operator-secret-hex",
                        operator_secret_hex,
                    ]
                    resumed = subprocess.run(resume_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    resumed_json = json.loads(resumed.stdout)
                    self.assertFalse(resumed_json["redemptions_paused"])

                    enable_auto_pause_cmd = [
                        str(CLI),
                        "mint_redemptions_auto_pause_enable",
                        "--url",
                        f"http://127.0.0.1:{port}/policy/redemptions",
                        "--operator-key-id",
                        operator_key_id,
                        "--operator-secret-hex",
                        operator_secret_hex,
                    ]
                    enabled = subprocess.run(enable_auto_pause_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    enabled_json = json.loads(enabled.stdout)
                    self.assertTrue(enabled_json["auto_pause_enabled"])

                    for notifier_id, kind, target, extra in [
                        ("ops-webhook", "webhook", f"http://127.0.0.1:{notifier_port}/webhook", []),
                        ("ops-alertmanager", "alertmanager", f"http://127.0.0.1:{notifier_port}/alertmanager", []),
                        ("ops-email", "email_spool", str(email_spool), ["--email-to", "ops@example.test", "--email-from", "mint@example.test"]),
                        ("ops-fail", "webhook", f"http://127.0.0.1:{notifier_port}/fail", ["--retry-max-attempts", "1", "--retry-backoff-seconds", "1"]),
                    ]:
                        notifier_cmd = [
                            str(CLI),
                            "mint_notifier_upsert",
                            "--url",
                            f"http://127.0.0.1:{port}/monitoring/notifiers",
                            "--operator-key-id",
                            operator_key_id,
                            "--operator-secret-hex",
                            operator_secret_hex,
                            "--notifier-id",
                            notifier_id,
                            "--kind",
                            kind,
                            "--target",
                            target,
                        ] + extra + (["--auth-type", "bearer", "--auth-token-secret-ref", "ops_webhook_bearer"] if notifier_id == "ops-webhook" else [])
                        subprocess.run(notifier_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)

                    notifiers_json = http_get_json(f"http://127.0.0.1:{port}/monitoring/notifiers")
                    webhook_notifier = next(item for item in notifiers_json["notifiers"] if item["notifier_id"] == "ops-webhook")
                    self.assertEqual(webhook_notifier["auth_token_secret_ref"], "ops_webhook_bearer")
                    self.assertNotIn("auth_token", webhook_notifier)
                    self.assertNotIn("integration-token", state_path.read_text(encoding="utf-8"))

                    pubkey = http_get_json(f"http://127.0.0.1:{port}/mint/key")
                    n = int(pubkey["modulus_hex"], 16)
                    e = int(pubkey["public_exponent"])
                    message = 123456789
                    r = 5
                    while math.gcd(r, n) != 1:
                        r += 2
                    blinded = (message * pow(r, e, n)) % n

                    blind_cmd = [
                        str(CLI),
                        "mint_issue_blinds",
                        "--url",
                        f"http://127.0.0.1:{port}/issuance/blind",
                        "--mint-deposit-ref",
                        mint_deposit_ref,
                        "--blind",
                        format(blinded, "x"),
                        "--note-amount",
                        "100000",
                    ]
                    blind = subprocess.run(blind_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    blind_lines = blind.stdout.splitlines()
                    signed_line = next(line for line in blind_lines if line.startswith("signed_blind[0]="))
                    note_ref_line = next(line for line in blind_lines if line.startswith("note_ref[0]="))
                    signed_blind = int(signed_line.split("=", 1)[1], 16)
                    note_ref = note_ref_line.split("=", 1)[1]
                    unblinded = (signed_blind * pow(r, -1, n)) % n
                    self.assertEqual(pow(unblinded, e, n), message)

                    plan_cmd = [
                        str(CLI),
                        "mint_reserve_consolidation_plan",
                        "--url",
                        f"http://127.0.0.1:{port}/reserves/consolidate_plan",
                        "--operator-key-id",
                        operator_key_id,
                        "--operator-secret-hex",
                        operator_secret_hex,
                    ]
                    plan = subprocess.run(plan_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    plan_json = json.loads(plan.stdout)
                    self.assertFalse(plan_json["available"])
                    self.assertIn("no consolidation candidates available", plan_json["reason"])

                    accounting = http_get_json(f"http://127.0.0.1:{port}/accounting/summary")
                    self.assertEqual(accounting["total_deposited"], 100000)
                    self.assertEqual(accounting["issued_blind_count"], 1)
                    self.assertEqual(accounting["issued_amount"], 100000)

                    invalid_status, invalid_body = http_post_json(
                        f"http://127.0.0.1:{port}/redemptions/create",
                        {
                            "notes": [note_ref],
                            "redeem_address": "not-a-finalis-address",
                            "amount": 100000,
                        },
                    )
                    self.assertEqual(invalid_status, HTTPStatus.BAD_REQUEST)
                    self.assertEqual(invalid_body["error"], "invalid redeem_address")

                    redeem_cmd = [
                        str(CLI),
                        "mint_redeem_create",
                        "--url",
                        f"http://127.0.0.1:{port}/redemptions/create",
                        "--redeem-address",
                        "sc1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaczjbkjy",
                        "--amount",
                        "100000",
                        "--note",
                        note_ref,
                    ]
                    redeem = subprocess.run(redeem_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    redeem_lines = dict(line.split("=", 1) for line in redeem.stdout.strip().splitlines())
                    batch_id = redeem_lines["redemption_batch_id"]

                    pending_status_cmd = [
                        str(CLI),
                        "mint_redeem_status",
                        "--url",
                        f"http://127.0.0.1:{port}/redemptions/status",
                        "--batch-id",
                        batch_id,
                    ]
                    pending_status = subprocess.run(pending_status_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    pending_lines = dict(line.split("=", 1) for line in pending_status.stdout.strip().splitlines())
                    self.assertEqual(pending_lines["state"], "pending")
                    self.assertEqual(pending_lines["l1_txid"], "")

                    lightserver.broadcast_spend_queue.append(
                        [
                            (utxo_txid_a, 0),
                            (utxo_txid_b, 1),
                        ]
                    )

                    approve_cmd = [
                        str(CLI),
                        "mint_redeem_approve_broadcast",
                        "--url",
                        f"http://127.0.0.1:{port}/redemptions/approve_broadcast",
                        "--batch-id",
                        batch_id,
                        "--operator-key-id",
                        operator_key_id,
                        "--operator-secret-hex",
                        operator_secret_hex,
                    ]
                    approve = subprocess.run(approve_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    approve_json = json.loads(approve.stdout)
                    self.assertTrue(approve_json["accepted"])
                    self.assertEqual(approve_json["state"], "broadcast")
                    self.assertTrue(approve_json["l1_txid"])

                    status_cmd = [
                        str(CLI),
                        "mint_redeem_status",
                        "--url",
                        f"http://127.0.0.1:{port}/redemptions/status",
                        "--batch-id",
                        batch_id,
                    ]
                    status = subprocess.run(status_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    status_lines = dict(line.split("=", 1) for line in status.stdout.strip().splitlines())
                    self.assertEqual(status_lines["state"], "broadcast")
                    self.assertTrue(status_lines["l1_txid"])
                    self.assertEqual(status_lines["amount"], "100000")

                    reserves = http_get_json(f"http://127.0.0.1:{port}/reserves")
                    self.assertEqual(reserves["available_reserve"], 0)
                    self.assertEqual(reserves["pending_spend_commitment_count"], 1)
                    self.assertEqual(reserves["pending_spend_input_count"], 2)
                    self.assertEqual(reserves["pending_spend_network_observed_count"], 1)
                    self.assertEqual(reserves["wallet_utxo_count"], 0)
                    self.assertEqual(reserves["wallet_utxo_value"], 0)
                    self.assertEqual(reserves["wallet_locked_utxo_count"], 0)
                    self.assertEqual(reserves["wallet_locked_utxo_value"], 0)
                    self.assertEqual(reserves["coin_selection_max_inputs"], 8)
                    self.assertFalse(reserves["recommend_consolidation"])
                    self.assertFalse(reserves["alert_fragmentation_threshold_breach"])
                    self.assertTrue(reserves["alert_reserve_exhaustion_risk"])
                    self.assertTrue(reserves["auto_pause_recommended"])
                    self.assertEqual(reserves["reserve_health"]["status"], "critical")

                    policy_after_risk = http_get_json(f"http://127.0.0.1:{port}/policy/redemptions")
                    self.assertTrue(policy_after_risk["redemptions_paused"])
                    self.assertTrue(policy_after_risk["auto_pause_enabled"])
                    self.assertIn("auto:", policy_after_risk["pause_reason"])

                    alert_history = http_get_json(f"http://127.0.0.1:{port}/monitoring/alerts/history")
                    self.assertGreaterEqual(len(alert_history["events"]), 1)
                    self.assertEqual(alert_history["events"][0]["event_type"], "policy.auto_pause")
                    for _ in range(20):
                        paths = {item["path"] for item in notifier.received}
                        if "/alertmanager" in paths and "/fail" in paths:
                            break
                        time.sleep(0.1)
                    self.assertGreaterEqual(len(notifier.received), 2)
                    self.assertIn("/alertmanager", {item["path"] for item in notifier.received})
                    self.assertIn("/fail", {item["path"] for item in notifier.received})
                    self.assertGreaterEqual(len(list(email_spool.glob("*.eml"))), 1)
                    auto_pause_event = alert_history["events"][0]
                    self.assertEqual(auto_pause_event["deliveries"]["ops-fail"]["status"], "dead_letter")

                    metrics_cmd = [
                        str(CLI),
                        "mint_reserve_metrics",
                        "--url",
                        f"http://127.0.0.1:{port}/monitoring/metrics",
                    ]
                    metrics = subprocess.run(metrics_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    self.assertIn("finalis_mint_auto_pause_recommended 1", metrics.stdout)
                    self.assertIn("finalis_mint_redemptions_paused 1", metrics.stdout)
                    self.assertIn("finalis_mint_dead_letter_count 2", metrics.stdout)
                    self.assertIn("finalis_mint_delivery_job_queue_size", metrics.stdout)

                    dashboard = urllib.request.urlopen(f"http://127.0.0.1:{port}/dashboard", timeout=5).read().decode("utf-8")
                    self.assertIn("finalis-mint dashboard", dashboard)
                    incidents = urllib.request.urlopen(f"http://127.0.0.1:{port}/dashboard/incidents", timeout=5).read().decode("utf-8")
                    self.assertIn("Incident view", incidents)

                    ack_cmd = [
                        str(CLI),
                        "mint_alert_ack",
                        "--url",
                        f"http://127.0.0.1:{port}/monitoring/events/ack",
                        "--event-id",
                        alert_history["events"][0]["event_id"],
                        "--operator-key-id",
                        operator_key_id,
                        "--operator-secret-hex",
                        operator_secret_hex,
                        "--note",
                        "seen",
                    ]
                    subprocess.run(ack_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    history_after_ack = http_get_json(f"http://127.0.0.1:{port}/monitoring/alerts/history")
                    acked = next(item for item in history_after_ack["events"] if item["event_id"] == alert_history["events"][0]["event_id"])
                    self.assertTrue(acked["acknowledged"])

                    silence_cmd = [
                        str(CLI),
                        "mint_alert_silence",
                        "--url",
                        f"http://127.0.0.1:{port}/monitoring/events/silence",
                        "--event-type",
                        "policy.auto_pause",
                        "--until",
                        "4102444800",
                        "--operator-key-id",
                        operator_key_id,
                        "--operator-secret-hex",
                        operator_secret_hex,
                        "--reason",
                        "maintenance",
                    ]
                    subprocess.run(silence_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    silences_cmd = [
                        str(CLI),
                        "mint_alert_silences",
                        "--url",
                        f"http://127.0.0.1:{port}/monitoring/events/silences",
                    ]
                    silences = subprocess.run(silences_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    silences_json = json.loads(silences.stdout)
                    self.assertEqual(silences_json["silences"][0]["event_type"], "policy.auto_pause")

                    event_policy_update_cmd = [
                        str(CLI),
                        "mint_event_policy_update",
                        "--url",
                        f"http://127.0.0.1:{port}/monitoring/events/policy",
                        "--operator-key-id",
                        operator_key_id,
                        "--operator-secret-hex",
                        operator_secret_hex,
                        "--retention-limit",
                        "64",
                        "--export-include-acknowledged",
                        "false",
                    ]
                    subprocess.run(event_policy_update_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    event_policy = http_get_json(f"http://127.0.0.1:{port}/monitoring/events/policy")
                    self.assertEqual(event_policy["event_retention_limit"], 64)
                    self.assertFalse(event_policy["export_include_acknowledged"])

                    dead_letters_cmd = [
                        str(CLI),
                        "mint_dead_letters",
                        "--url",
                        f"http://127.0.0.1:{port}/monitoring/dead_letters",
                    ]
                    dead_letters = subprocess.run(dead_letters_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    dead_letters_json = json.loads(dead_letters.stdout)
                    self.assertGreaterEqual(len(dead_letters_json["dead_letters"]), 2)
                    self.assertTrue(all(item["notifier_id"] == "ops-fail" for item in dead_letters_json["dead_letters"]))

                    fix_notifier_cmd = [
                        str(CLI),
                        "mint_notifier_upsert",
                        "--url",
                        f"http://127.0.0.1:{port}/monitoring/notifiers",
                        "--operator-key-id",
                        operator_key_id,
                        "--operator-secret-hex",
                        operator_secret_hex,
                        "--notifier-id",
                        "ops-fail",
                        "--kind",
                        "webhook",
                        "--target",
                        f"http://127.0.0.1:{notifier_port}/webhook",
                        "--retry-max-attempts",
                        "2",
                        "--retry-backoff-seconds",
                        "1",
                    ]
                    subprocess.run(fix_notifier_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)

                    replay_cmd = [
                        str(CLI),
                        "mint_dead_letter_replay",
                        "--url",
                        f"http://127.0.0.1:{port}/monitoring/dead_letters/replay",
                        "--dead-letter-id",
                        dead_letters_json["dead_letters"][0]["dead_letter_id"],
                        "--operator-key-id",
                        operator_key_id,
                        "--operator-secret-hex",
                        operator_secret_hex,
                    ]
                    subprocess.run(replay_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    replay_event = None
                    for _ in range(20):
                        history_after_replay = http_get_json(f"http://127.0.0.1:{port}/monitoring/alerts/history")
                        replay_event = next((item for item in history_after_replay["events"] if item["event_type"] == "dead_letter.replayed"), None)
                        if replay_event is not None:
                            break
                        time.sleep(0.1)
                    self.assertIsNotNone(replay_event)
                    self.assertTrue(all(item["event_type"] != "worker.lease_takeover" for item in history_after_replay["events"]))

                    incident_cmd = [
                        str(CLI),
                        "mint_incident_timeline_export",
                        "--url",
                        f"http://127.0.0.1:{port}/monitoring/incidents/export",
                    ]
                    incident = subprocess.run(incident_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    incident_json = json.loads(incident.stdout)
                    self.assertTrue(incident_json["signature_hex"])
                    self.assertGreaterEqual(len(incident_json["payload"]["dead_letters"]), 1)
                    self.assertGreaterEqual(len(incident_json["payload"]["events"]), 1)
                    l1_txid = status_lines["l1_txid"]
                    lightserver.tip_height = 20
                    lightserver.tx_heights[l1_txid] = 20

                    finalized = subprocess.run(status_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    finalized_lines = dict(line.split("=", 1) for line in finalized.stdout.strip().splitlines())
                    self.assertEqual(finalized_lines["state"], "finalized")
                    self.assertEqual(finalized_lines["l1_txid"], l1_txid)
                    self.assertEqual(finalized_lines["amount"], "100000")

                    reserves_after_final = http_get_json(f"http://127.0.0.1:{port}/reserves")
                    self.assertEqual(reserves_after_final["pending_spend_commitment_count"], 0)

                    audit_cmd = [
                        str(CLI),
                        "mint_audit_export",
                        "--url",
                        f"http://127.0.0.1:{port}/audit/export",
                        "--operator-key-id",
                        operator_key_id,
                        "--operator-secret-hex",
                        operator_secret_hex,
                    ]
                    audit = subprocess.run(audit_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    audit_json = json.loads(audit.stdout)
                    self.assertEqual(len(audit_json["payload"]["issuances"]), 1)
                    self.assertEqual(audit_json["payload"]["reserves"]["pending_spend_commitment_count"], 0)
                    self.assertEqual(audit_json["payload"]["reserves"]["finalized_redemption_amount"], 100000)
                    self.assertEqual(audit_json["payload"]["reserves"]["coin_selection_max_inputs"], 8)
                    self.assertTrue(audit_json["payload"]["reserves"]["alert_reserve_exhaustion_risk"])
                    self.assertEqual(audit_json["payload"]["redemptions"][0]["coin_selection_policy"], "smallest-sufficient-non-dust-change")
                    self.assertEqual(audit_json["payload"]["redemptions"][0]["change_value"], 9000)
                    self.assertEqual(len(audit_json["payload"]["redemptions"][0]["selected_utxos"]), 2)
                    self.assertTrue(audit_json["signature_hex"])

                    attest_cmd = [
                        str(CLI),
                        "mint_attest_reserves",
                        "--url",
                        f"http://127.0.0.1:{port}/attestations/reserves",
                    ]
                    attestation = subprocess.run(attest_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    attest_json = json.loads(attestation.stdout)
                    self.assertEqual(attest_json["payload"]["reserve_balance"], 0)
                    self.assertEqual(attest_json["payload"]["wallet_locked_utxo_count"], 0)
                    self.assertEqual(attest_json["payload"]["finalized_redemption_amount"], 100000)
                    self.assertTrue(attest_json["payload"]["alert_reserve_exhaustion_risk"])
                    self.assertTrue(attest_json["payload"]["auto_pause_recommended"])
                    self.assertEqual(attest_json["payload"]["reserve_health"]["status"], "critical")
                    self.assertTrue(attest_json["signature_hex"])

                    lightserver.utxos_by_scripthash[reserve_scripthash] = [
                        {
                            "txid": "88" * 32,
                            "vout": 0,
                            "value": 500,
                            "height": 2,
                            "script_pubkey_hex": "",
                        },
                        {
                            "txid": "99" * 32,
                            "vout": 1,
                            "value": 700,
                            "height": 2,
                            "script_pubkey_hex": "",
                        },
                        {
                            "txid": "aa" * 32,
                            "vout": 2,
                            "value": 3000,
                            "height": 2,
                            "script_pubkey_hex": "",
                        },
                    ]
                    lightserver.broadcast_spend_queue.append(
                        [
                            ("88" * 32, 0),
                            ("99" * 32, 1),
                            ("aa" * 32, 2),
                        ]
                    )
                    consolidation_plan = subprocess.run(plan_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    consolidation_plan_json = json.loads(consolidation_plan.stdout)
                    self.assertTrue(consolidation_plan_json["available"])
                    self.assertEqual(consolidation_plan_json["input_count"], 3)
                    self.assertEqual(len(consolidation_plan_json["selected_utxos"]), 3)
                    self.assertEqual(consolidation_plan_json["estimated_post_action"]["wallet_utxo_count"], 1)
                    self.assertFalse(consolidation_plan_json["estimated_post_action"]["alerts"]["recommend_consolidation"])
                    consolidate_cmd = [
                        str(CLI),
                        "mint_reserve_consolidate",
                        "--url",
                        f"http://127.0.0.1:{port}/reserves/consolidate",
                        "--operator-key-id",
                        operator_key_id,
                        "--operator-secret-hex",
                        operator_secret_hex,
                    ]
                    consolidate = subprocess.run(consolidate_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    consolidate_json = json.loads(consolidate.stdout)
                    self.assertTrue(consolidate_json["accepted"])
                    self.assertEqual(consolidate_json["input_count"], 3)
                    self.assertEqual(consolidate_json["total_input_value"], 4200)
                    self.assertEqual(consolidate_json["output_value"], 3200)

                    reserves_after_consolidation = http_get_json(f"http://127.0.0.1:{port}/reserves")
                    self.assertEqual(reserves_after_consolidation["wallet_utxo_count"], 0)
                    self.assertTrue(reserves_after_consolidation["alert_reserve_exhaustion_risk"])

                    reserve_health_cmd = [
                        str(CLI),
                        "mint_reserve_health",
                        "--url",
                        f"http://127.0.0.1:{port}/monitoring/reserve_health",
                    ]
                    reserve_health = subprocess.run(reserve_health_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    reserve_health_json = json.loads(reserve_health.stdout)
                    self.assertEqual(reserve_health_json["status"], "critical")
                    self.assertTrue(reserve_health_json["alerts"]["auto_pause_recommended"])

                    consolidation_txid = consolidate_json["l1_txid"]
                    lightserver.tip_height = 25
                    lightserver.tx_heights[consolidation_txid] = 25

                    final_audit = subprocess.run(audit_cmd, cwd=REPO_ROOT, check=True, text=True, capture_output=True)
                    final_audit_json = json.loads(final_audit.stdout)
                    self.assertEqual(len(final_audit_json["payload"]["consolidations"]), 1)
                    self.assertEqual(final_audit_json["payload"]["consolidations"][0]["state"], "finalized")
                    self.assertEqual(final_audit_json["payload"]["consolidations"][0]["coin_selection_policy"], "smallest-first-consolidation")

                    operator_pub = http_get_json(f"http://127.0.0.1:{port}/operator/key")
                    self.assertEqual(operator_pub["operator_key_id"], operator_key_id)
                finally:
                    worker_proc.terminate()
                    try:
                        worker_proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        worker_proc.kill()
                        worker_proc.wait(timeout=5)
                    if worker_proc.stdout is not None:
                        worker_proc.stdout.close()
                    if worker_proc.stderr is not None:
                        worker_proc.stderr.close()
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
                    if proc.stdout is not None:
                        proc.stdout.close()
                    if proc.stderr is not None:
                        proc.stderr.close()
        finally:
            lightserver.stop()
            notifier.stop()


if __name__ == "__main__":
    unittest.main()
