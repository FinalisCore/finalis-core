from __future__ import annotations

import importlib.util
import sys
import tempfile
import subprocess
import unittest
from pathlib import Path


def load_server_module():
    server_path = Path(__file__).with_name("server.py")
    spec = importlib.util.spec_from_file_location("finalis_mint_server", server_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load server module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


server = load_server_module()


class MintStateTests(unittest.TestCase):
    def test_policy_persists_and_blocks_redemptions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            state = server.MintState(state_path)
            state.register_deposit(
                {
                    "chain": "mainnet",
                    "deposit_txid": "11" * 32,
                    "deposit_vout": 1,
                    "mint_id": "22" * 32,
                    "recipient_pubkey_hash": "33" * 20,
                    "amount": 1000,
                    "mint_deposit_ref": "ref-1",
                }
            )
            issuance = state.record_issuance("ref-1", ["aa"], ["bb"], [1000])
            policy = state.update_policy(True, "reserve low")
            self.assertTrue(policy["redemptions_paused"])
            self.assertEqual(policy["pause_reason"], "reserve low")

            reloaded = server.MintState(state_path)
            self.assertTrue(reloaded.policy()["redemptions_paused"])
            with self.assertRaises(ValueError):
                reloaded.create_redemption(
                    {
                        "redemption_batch_id": "batch-1",
                        "notes": issuance["note_refs"],
                        "redeem_address": "sc1example",
                        "amount": 1000,
                        "state": "pending",
                        "l1_txid": "",
                    }
                )

    def test_event_log_persists(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            state = server.MintState(state_path)
            event = state.append_event("policy.auto_pause", {"reason": "reserve exhaustion risk"})
            self.assertEqual(event["event_type"], "policy.auto_pause")

            reloaded = server.MintState(state_path)
            events = reloaded.list_events(10)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["payload"]["reason"], "reserve exhaustion risk")

    def test_event_ack_silence_and_notifier_persist(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            state = server.MintState(state_path)
            event = state.append_event("policy.auto_pause", {"reason": "reserve exhaustion risk"})
            acked = state.acknowledge_event(event["event_id"], "seen")
            self.assertTrue(acked["acknowledged"])
            self.assertEqual(acked["ack_note"], "seen")

            silence = state.add_silence("policy.auto_pause", 4102444800, "maintenance")
            self.assertEqual(silence["event_type"], "policy.auto_pause")
            self.assertTrue(state.event_silenced("policy.auto_pause"))

            notifier = state.upsert_notifier(
                {
                    "notifier_id": "ops-webhook",
                    "kind": "webhook",
                    "target": "http://127.0.0.1:9/hook",
                    "enabled": True,
                    "auth_type": "bearer",
                    "auth_token_secret_ref": "ops_token",
                }
            )
            self.assertEqual(notifier["notifier_id"], "ops-webhook")
            self.assertEqual(notifier["auth_token_secret_ref"], "ops_token")

            reloaded = server.MintState(state_path)
            self.assertEqual(reloaded.list_events(10)[0]["ack_note"], "seen")
            self.assertEqual(reloaded.list_silences(True)[0]["reason"], "maintenance")
            self.assertEqual(reloaded.list_notifiers()[0]["kind"], "webhook")
            self.assertEqual(reloaded.list_notifiers()[0]["auth_token_secret_ref"], "ops_token")

    def test_delivery_jobs_persist_and_reload(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            state = server.MintState(state_path)
            event = state.append_event("policy.auto_pause", {"reason": "reserve exhaustion risk"})
            job = state.enqueue_delivery_job(event["event_id"], "ops-webhook", 123)
            self.assertEqual(job["status"], "pending")
            self.assertEqual(len(state.list_due_delivery_jobs(200, 10)), 1)
            state.update_delivery_job(job["job_id"], "pending", attempts=2, last_error="boom", next_run_at=300)

            reloaded = server.MintState(state_path)
            jobs = reloaded.list_delivery_jobs(10)
            self.assertEqual(len(jobs), 1)
            self.assertEqual(jobs[0]["notifier_id"], "ops-webhook")
            self.assertEqual(jobs[0]["attempts"], 2)
            self.assertEqual(jobs[0]["last_error"], "boom")

    def test_secret_helper_resolves_from_dir(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            secret_dir = Path(td) / "secrets"
            secret_dir.mkdir(parents=True, exist_ok=True)
            (secret_dir / "ops_token").write_text("topsecret\n", encoding="utf-8")
            helper = Path(__file__).with_name("secret_helper.py")
            proc = subprocess.run(
                ["python3", str(helper), "--dir", str(secret_dir), "ops_token"],
                check=True,
                text=True,
                capture_output=True,
            )
            self.assertEqual(proc.stdout.strip(), "topsecret")

    def test_worker_lease_takeover_on_stale_lock(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            lock_path = Path(td) / "worker.lock"
            stale = {
                "owner_pid": 999999,
                "heartbeat_at": 1,
                "acquired_at": 1,
                "mode": "worker",
                "stale_timeout_seconds": 5,
            }
            lock_path.write_text(__import__("json").dumps(stale), encoding="utf-8")
            lock = server.WorkerLeaderLock(lock_path, stale_timeout_seconds=5)
            result = lock.acquire_status("worker")
            self.assertTrue(result["acquired"])
            self.assertTrue(result["takeover"])
            self.assertEqual(result["stale_owner_pid"], "999999")

    def test_systemd_packaging_assets_exist(self) -> None:
        root = Path(__file__).parent / "systemd"
        server_unit = root / "finalis-mint-server.service"
        worker_unit = root / "finalis-mint-worker.service"
        env_example = root / "finalis-mint.env.example"
        install_script = root / "install_finalis_mint.sh"
        tmpfiles = root / "finalis-mint.tmpfiles.conf"
        self.assertTrue(server_unit.exists())
        self.assertTrue(worker_unit.exists())
        self.assertTrue(env_example.exists())
        self.assertTrue(install_script.exists())
        self.assertTrue(tmpfiles.exists())
        self.assertIn("ExecStart=", server_unit.read_text(encoding="utf-8"))
        self.assertIn("FINALIS_MINT_NOTIFIER_SECRET_HELPER_CMD", env_example.read_text(encoding="utf-8"))

    def test_register_deposit_persists_and_reloads(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            state = server.MintState(state_path)
            deposit = {
                "chain": "mainnet",
                "deposit_txid": "11" * 32,
                "deposit_vout": 1,
                "mint_id": "22" * 32,
                "recipient_pubkey_hash": "33" * 20,
                "amount": 1000,
                "mint_deposit_ref": "ref-1",
            }
            state.register_deposit(deposit)

            reloaded = server.MintState(state_path)
            got = reloaded.get_deposit("ref-1")
            self.assertIsNotNone(got)
            self.assertEqual(got["amount"], 1000)
            self.assertEqual(got["recipient_pubkey_hash"], "33" * 20)

    def test_register_deposit_is_idempotent_and_preserves_issuance_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            state = server.MintState(state_path)
            deposit = {
                "chain": "mainnet",
                "deposit_txid": "11" * 32,
                "deposit_vout": 1,
                "mint_id": "22" * 32,
                "recipient_pubkey_hash": "33" * 20,
                "amount": 1000,
                "mint_deposit_ref": "ref-1",
            }
            state.register_deposit(deposit)
            issuance = state.record_issuance("ref-1", ["aa"], ["bb"], [400])

            again = state.register_deposit(deposit)
            self.assertEqual(again["issued_amount"], 400)
            self.assertEqual(again["issued_blind_count"], 1)
            self.assertEqual(again["issuance_ids"], [issuance["issuance_id"]])

            got = state.get_deposit("ref-1")
            self.assertEqual(got["issued_amount"], 400)
            self.assertEqual(got["issued_blind_count"], 1)
            self.assertEqual(got["issuance_ids"], [issuance["issuance_id"]])

    def test_register_deposit_rejects_conflicting_reregistration(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            state = server.MintState(state_path)
            state.register_deposit(
                {
                    "chain": "mainnet",
                    "deposit_txid": "11" * 32,
                    "deposit_vout": 1,
                    "mint_id": "22" * 32,
                    "recipient_pubkey_hash": "33" * 20,
                    "amount": 1000,
                    "mint_deposit_ref": "ref-1",
                }
            )

            with self.assertRaises(ValueError):
                state.register_deposit(
                    {
                        "chain": "mainnet",
                        "deposit_txid": "11" * 32,
                        "deposit_vout": 1,
                        "mint_id": "22" * 32,
                        "recipient_pubkey_hash": "33" * 20,
                        "amount": 2000,
                        "mint_deposit_ref": "ref-1",
                    }
                )

    def test_redemption_marks_notes_spent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            state = server.MintState(state_path)
            state.register_deposit(
                {
                    "chain": "mainnet",
                    "deposit_txid": "11" * 32,
                    "deposit_vout": 1,
                    "mint_id": "22" * 32,
                    "recipient_pubkey_hash": "33" * 20,
                    "amount": 1000,
                    "mint_deposit_ref": "ref-1",
                }
            )
            issuance = state.record_issuance("ref-1", ["aa", "bb"], ["cc", "dd"], [150, 250])
            redemption = {
                "redemption_batch_id": "batch-1",
                "notes": issuance["note_refs"],
                "redeem_address": "sc1example",
                "amount": 400,
                "state": "pending",
                "l1_txid": "",
            }
            state.create_redemption(redemption)
            self.assertTrue(state.note_already_spent(issuance["note_refs"][0]))
            self.assertTrue(state.note_already_spent(issuance["note_refs"][1]))
            self.assertFalse(state.note_already_spent("note-c"))

    def test_issuance_persists_and_rejects_duplicate_blinds(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            state = server.MintState(state_path)
            state.register_deposit(
                {
                    "chain": "mainnet",
                    "deposit_txid": "11" * 32,
                    "deposit_vout": 1,
                    "mint_id": "22" * 32,
                    "recipient_pubkey_hash": "33" * 20,
                    "amount": 1000,
                    "mint_deposit_ref": "ref-1",
                }
            )

            issuance = state.record_issuance("ref-1", ["aa", "bb"], ["cc", "dd"], [400, 600])
            self.assertEqual(issuance["note_count"], 2)
            self.assertEqual(issuance["note_amounts"], [400, 600])
            self.assertEqual(len(issuance["note_refs"]), 2)

            reloaded = server.MintState(state_path)
            dep = reloaded.get_deposit("ref-1")
            self.assertEqual(dep["issued_blind_count"], 2)
            self.assertEqual(dep["issued_amount"], 1000)
            self.assertIsNotNone(reloaded.get_note_record(issuance["note_refs"][0]))

            with self.assertRaises(ValueError):
                reloaded.record_issuance("ref-1", ["aa"], ["ee"], [100])

    def test_rejected_redemption_releases_notes_and_finalized_counts_in_reserves(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            state = server.MintState(state_path)
            state.register_deposit(
                {
                    "chain": "mainnet",
                    "deposit_txid": "11" * 32,
                    "deposit_vout": 1,
                    "mint_id": "22" * 32,
                    "recipient_pubkey_hash": "33" * 20,
                    "amount": 1000,
                    "mint_deposit_ref": "ref-1",
                }
            )
            issuance = state.record_issuance("ref-1", ["aa", "bb"], ["cc", "dd"], [150, 250])
            state.create_redemption(
                {
                    "redemption_batch_id": "batch-1",
                    "notes": issuance["note_refs"],
                    "redeem_address": "sc1example",
                    "amount": 400,
                    "state": "pending",
                    "l1_txid": "",
                }
            )
            self.assertTrue(state.note_already_spent(issuance["note_refs"][0]))
            state.update_redemption("batch-1", "rejected")
            note = state.get_note_record(issuance["note_refs"][0])
            self.assertEqual(note["state"], "issued")

            second = state.record_issuance("ref-1", ["cc"], ["ee"], [250])
            state.create_redemption(
                {
                    "redemption_batch_id": "batch-2",
                    "notes": second["note_refs"],
                    "redeem_address": "sc1example",
                    "amount": 250,
                    "state": "pending",
                    "l1_txid": "",
                }
            )
            state.update_redemption("batch-2", "finalized", "44" * 32)
            reserves = state.reserve_summary()
            accounting = state.accounting_summary()
            self.assertEqual(reserves["total_deposited"], 1000)
            self.assertEqual(reserves["finalized_redemption_amount"], 250)
            self.assertEqual(reserves["available_reserve"], 750)
            self.assertEqual(accounting["active_note_locks"], 1)

    def test_audit_and_attestation_export_cover_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            state = server.MintState(state_path)
            state.register_deposit(
                {
                    "chain": "mainnet",
                    "deposit_txid": "11" * 32,
                    "deposit_vout": 1,
                    "mint_id": "22" * 32,
                    "recipient_pubkey_hash": "33" * 20,
                    "amount": 1000,
                    "mint_deposit_ref": "ref-1",
                }
            )
            state.record_issuance("ref-1", ["aa"], ["bb"], [1000])
            audit = state.audit_export("22" * 32)
            attest = state.reserve_attestation("22" * 32)
            self.assertEqual(len(audit["deposits"]), 1)
            self.assertEqual(len(audit["issuances"]), 1)
            self.assertEqual(attest["mint_id"], "22" * 32)
            self.assertTrue(attest["state_hash"])

    def test_consolidation_persists_and_exports(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            state = server.MintState(state_path)
            item = state.record_consolidation(
                {
                    "consolidation_id": "cons-1",
                    "state": "broadcast",
                    "l1_txid": "44" * 32,
                    "selected_utxos": [{"txid": "55" * 32, "vout": 0, "value": 2000}],
                    "total_input_value": 2000,
                    "output_value": 1000,
                    "fee": 1000,
                    "coin_selection_policy": "smallest-first-consolidation",
                }
            )
            self.assertEqual(item["state"], "broadcast")
            reloaded = server.MintState(state_path)
            got = reloaded.get_consolidation("cons-1")
            self.assertIsNotNone(got)
            self.assertEqual(got["l1_txid"], "44" * 32)
            reloaded.update_consolidation("cons-1", "finalized", "44" * 32)
            audit = reloaded.audit_export("22" * 32)
            self.assertEqual(len(audit["consolidations"]), 1)
            self.assertEqual(audit["consolidations"][0]["state"], "finalized")

    def test_blind_signer_signs_and_verifies(self) -> None:
        signer = server.BlindSigner.from_seed("seed-x", bits=256)
        message = 123456789
        signature = int(signer.sign_blinded_hex(format(message, "x")), 16)
        self.assertEqual(pow(signature, signer.e, signer.n), message)

    def test_blind_signer_is_deterministic_for_seed(self) -> None:
        a = server.BlindSigner.from_seed("seed-a", bits=256)
        b = server.BlindSigner.from_seed("seed-a", bits=256)
        self.assertEqual(a.n, b.n)
        self.assertEqual(a.e, b.e)
        self.assertEqual(a.d, b.d)


if __name__ == "__main__":
    unittest.main()
