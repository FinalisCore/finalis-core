# SPDX-License-Identifier: MIT
"""Offline tests of faucet_core with a fake RPC and CLI: python3 -m unittest test_faucet_core"""

import tempfile
import unittest

from faucet_core import UNITS_PER_FLS, Faucet, Store

BOND = 150 * UNITS_PER_FLS
BUFFER = 1 * UNITS_PER_FLS
FAUCET = "tsc1faucet"


class FakeRpc:
    def __init__(self):
        self.balance = 0
        self.finalized = set()

    def validate_address(self, address):
        if address.startswith("tsc1"):
            return {"valid": True, "server_network_match": True, "normalized_address": address}
        if address.startswith("sc1"):
            return {"valid": True, "server_network_match": False}
        return {"valid": False, "error": "bad checksum"}

    def balance_units(self, address):
        assert address == FAUCET
        return self.balance

    def tx_finalized(self, txid):
        return txid in self.finalized


class FakeCli:
    def __init__(self, rpc):
        self.rpc = rpc
        self.sent = []
        self.fail_next = False

    def min_bond_units(self):
        return BOND

    def send(self, address, units):
        if self.fail_next:
            return "deadbeef", False, "fee too low"
        txid = f"tx{len(self.sent)}"
        self.sent.append((address, units))
        self.rpc.balance -= units
        return txid, True, ""


class FaucetTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".sqlite")
        self.rpc = FakeRpc()
        self.cli = FakeCli(self.rpc)
        self.faucet = Faucet(Store(self.tmp.name), self.rpc, self.cli, FAUCET, BUFFER, 575_000_000)

    def tearDown(self):
        self.faucet.store.db.close()
        self.tmp.close()

    def test_rejects_invalid_and_mainnet_addresses(self):
        self.assertIn("not a valid address", self.faucet.request("u1", "garbage"))
        self.assertIn("not a testnet address", self.faucet.request("u1", "sc1abc"))
        self.assertIsNone(self.faucet.store.by_user("u1"))

    def test_one_grant_per_account_and_per_address(self):
        self.assertIn("queue", self.faucet.request("u1", "tsc1a"))
        self.assertIn("already have a grant", self.faucet.request("u1", "tsc1b"))
        self.assertIn("already has a grant", self.faucet.request("u2", "tsc1a"))

    def test_only_the_first_max_grants_are_given(self):
        faucet = Faucet(self.faucet.store, self.rpc, self.cli, FAUCET, BUFFER, 575_000_000, max_grants=2)
        self.assertIn("grant 1 of 2", faucet.request("u1", "tsc1a"))
        self.assertIn("grant 2 of 2", faucet.request("u2", "tsc1b"))
        reply = faucet.request("u3", "tsc1c")
        self.assertIn("All 2 faucet grants are taken", reply)
        self.assertIsNone(faucet.store.by_user("u3"))
        # A failed payment frees its slot.
        faucet.store.update(faucet.store.by_user("u1").id, state="failed", error="x")
        self.assertIn("grant 2 of 2", faucet.request("u3", "tsc1c"))

    def test_waits_for_funds_then_pays_bond_plus_buffer_in_order(self):
        self.faucet.request("u1", "tsc1a")
        reply = self.faucet.request("u2", "tsc1b")
        self.assertIn("place in the queue: 2", reply)
        self.rpc.balance = BOND  # less than bond + buffer
        self.assertEqual(self.faucet.tick(), [])
        self.assertEqual(self.cli.sent, [])
        self.rpc.balance = 2 * (BOND + BUFFER)
        events = self.faucet.tick()
        self.assertEqual(self.cli.sent, [("tsc1a", BOND + BUFFER)])
        self.assertEqual(events[0].user_id, "u1")
        # Next payment waits until the first is final (its change is not spendable before).
        self.assertEqual(self.faucet.tick(), [])
        self.assertEqual(len(self.cli.sent), 1)
        self.rpc.finalized.add("tx0")
        self.assertIn("final", self.faucet.tick()[0].text)
        self.faucet.tick()
        self.assertEqual(self.cli.sent[1], ("tsc1b", BOND + BUFFER))

    def test_failed_send_is_not_retried(self):
        self.faucet.request("u1", "tsc1a")
        self.rpc.balance = 10 * BOND
        self.cli.fail_next = True
        self.assertIn("failed", self.faucet.tick()[0].text)
        self.cli.fail_next = False
        self.assertEqual(self.faucet.tick(), [])  # never paid twice automatically
        self.assertEqual(self.faucet.store.by_user("u1").state, "failed")

    def test_eta_reports_hours_from_income(self):
        self.rpc.balance = 0
        reply = self.faucet.request("u1", "tsc1a")
        blocks = -(-(BOND + BUFFER) // 575_000_000)
        self.assertIn(f"({blocks} blocks)", reply)


if __name__ == "__main__":
    unittest.main()
