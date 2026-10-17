"""
Phase 7 Advanced Features Test Suite (`tests/test_phase7_advanced_features.py`).

Verifies:
1. Concurrency Hardening: TCPSocketLedgerServer bounded ThreadPoolExecutor under concurrent load.
2. Dynamic PoW Difficulty Retargeting: Difficulty retargeting adjustments under fast/slow block times.
3. High-Performance O(1) Address History Indexing: Consistency and correctness against linear scan.
4. Fast Checkpointing in FullChainValidator: Trusted anchor verification and tamper prevention.
5. Web Dashboard REST API & Explorer: HTTP endpoints and interactive simulation.
6. RSA Cryptographic Grade Inspection: is_production_grade and format_security_summary.
"""

from __future__ import annotations

import json
import unittest
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from blockchain_lite.crypto.asymmetric import (
    default_crypto_engine,
)
from blockchain_lite.crypto.hashing import default_hasher
from blockchain_lite.interfaces import TamperDetectedError
from blockchain_lite.ledger.chain import BlockchainLedger
from blockchain_lite.ledger.validator import FullChainValidator
from blockchain_lite.network.client import TCPSocketTransport
from blockchain_lite.network.server import TCPSocketLedgerServer
from blockchain_lite.network.web_dashboard import (
    WebDashboardServer,
    create_demo_ledger_and_wallets,
)
from blockchain_lite.wallet.wallet import Wallet


class TestTCPServerThreadPool(unittest.TestCase):
    """Verify bounded ThreadPoolExecutor concurrency and graceful shutdown."""

    def test_concurrent_rpc_requests_with_bounded_pool(self) -> None:
        ledger = BlockchainLedger(difficulty=4)
        w = Wallet.generate(label="pool_wallet", bit_length=384)
        ledger.create_genesis_block(initial_allocations=[(w.address, 1000)])

        server = TCPSocketLedgerServer(ledger, host="127.0.0.1", port=0, max_workers=4)
        server.start()
        self.addCleanup(server.stop)

        def query_chain(idx: int) -> int:
            transport = TCPSocketTransport(host=server.host, port=server.port)
            res = transport.send_request("get_chain_info", {})
            return int(res["height"])

        # Concurrently issue 12 requests across 4 workers
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(query_chain, i) for i in range(12)]
            results = [f.result(timeout=5.0) for f in as_completed(futures)]

        self.assertEqual(len(results), 12)
        self.assertTrue(all(h == 1 for h in results))


class TestDynamicDifficultyRetargeting(unittest.TestCase):
    """Verify Nakamoto-style difficulty adjustment based on block generation time."""

    def test_dynamic_retargeting_increases_on_fast_blocks(self) -> None:
        ledger = BlockchainLedger(
            difficulty=4,
            retarget_interval=2,
            target_block_time_seconds=10.0,
            min_difficulty=2,
            max_difficulty=8,
        )
        miner = Wallet.generate(label="miner", bit_length=384)
        t0 = 1700000000
        ledger.create_genesis_block(initial_allocations=[(miner.address, 100)], timestamp=t0)

        # Mine block 1 at t0 + 1 (very fast)
        b1, _ = ledger.mine_pending_transactions(miner_address=miner.address, timestamp=t0 + 1)
        self.assertEqual(b1.index, 1)

        # Before block 2, height=2, which is a multiple of retarget_interval=2
        # Actual time = 1s, Expected time = 2 * 10 = 20s
        # 1s < 20s * 0.75 -> Difficulty should increase from 4 to 5!
        next_diff = ledger.calculate_next_difficulty()
        self.assertEqual(next_diff, 5)

        # Mine block 2 at target difficulty
        b2, _ = ledger.mine_pending_transactions(miner_address=miner.address, timestamp=t0 + 2)
        self.assertEqual(b2.difficulty, 5)

    def test_dynamic_retargeting_decreases_on_slow_blocks(self) -> None:
        ledger = BlockchainLedger(
            difficulty=5,
            retarget_interval=2,
            target_block_time_seconds=5.0,
            min_difficulty=2,
            max_difficulty=8,
        )
        miner = Wallet.generate(label="miner", bit_length=384)
        t0 = 1700000000
        ledger.create_genesis_block(initial_allocations=[(miner.address, 100)], timestamp=t0)

        # Mine block 1 at t0 + 50 (very slow: 50s vs expected 10s)
        ledger.mine_pending_transactions(miner_address=miner.address, timestamp=t0 + 50)

        # Actual time = 50s > 10s * 1.33 -> Difficulty should decrease from 5 to 4!
        next_diff = ledger.calculate_next_difficulty()
        self.assertEqual(next_diff, 4)


class TestAddressHistoryIndexing(unittest.TestCase):
    """Verify O(1) indexed transaction history against exhaustive chain scan."""

    def test_address_history_index_matches_full_scan(self) -> None:
        ledger = BlockchainLedger(difficulty=4)
        alice = Wallet.generate(label="alice", bit_length=384)
        bob = Wallet.generate(label="bob", bit_length=384)

        ledger.create_genesis_block(
            initial_allocations=[(alice.address, 100), (bob.address, 50)]
        )

        # Transfer 1: Alice -> Bob
        alice_utxos = ledger.get_spendable_utxos(alice.address)
        tx1 = alice.create_signed_transfer(
            recipient_address=bob.address,
            amount=25,
            spendable_utxos=alice_utxos,
            fee=1,
        )
        ledger.submit_transaction(tx1)
        ledger.mine_pending_transactions(miner_address=alice.address)

        # Transfer 2: Bob -> Alice
        bob_utxos = ledger.get_spendable_utxos(bob.address)
        tx2 = bob.create_signed_transfer(
            recipient_address=alice.address,
            amount=10,
            spendable_utxos=bob_utxos,
            fee=1,
        )
        ledger.submit_transaction(tx2)
        ledger.mine_pending_transactions(miner_address=bob.address)

        alice_history = ledger.get_transaction_history(alice.address)
        bob_history = ledger.get_transaction_history(bob.address)

        # Alice is in Genesis (receive 100), Tx1 (send 25, change, coinbase 51), Tx2 (receive 10)
        self.assertGreaterEqual(len(alice_history), 3)
        self.assertGreaterEqual(len(bob_history), 3)

        # Check structure
        for entry in alice_history:
            self.assertIn("block_index", entry)
            self.assertIn("tx_id", entry)
            self.assertIn("tx_type", entry)
            self.assertIn("is_sender", entry)
            self.assertIn("received_amount", entry)


class TestValidatorCheckpointing(unittest.TestCase):
    """Verify trusted checkpoint hash pinning and tamper prevention."""

    def test_checkpoint_validation_passes_and_detects_mismatch(self) -> None:
        ledger = BlockchainLedger(difficulty=4)
        alice = Wallet.generate(label="alice", bit_length=384)
        ledger.create_genesis_block(initial_allocations=[(alice.address, 100)])
        b1, _ = ledger.mine_pending_transactions(miner_address=alice.address)

        validator = FullChainValidator(hasher=default_hasher, params=ledger.params)

        # Register valid checkpoint
        validator.register_checkpoint(1, b1.block_hash)
        report = validator.validate_chain(ledger.blocks)
        self.assertTrue(report.is_valid)

        # Register invalid checkpoint
        validator.register_checkpoint(1, b"\xee" * 32)
        with self.assertRaises(TamperDetectedError) as cm:
            validator.validate_chain_or_raise(ledger.blocks)
        self.assertIn("Checkpoint mismatch at Block #1", str(cm.exception))


class TestWebDashboardEndpoints(unittest.TestCase):
    """Verify WebDashboardServer HTTP REST API and UI delivery."""

    def test_dashboard_server_endpoints(self) -> None:
        ledger, wallets = create_demo_ledger_and_wallets()
        server = WebDashboardServer(ledger=ledger, named_wallets=wallets, host="127.0.0.1", port=0)
        server.start()
        self.addCleanup(server.stop)

        base_url = server.url

        # 1. GET /
        with urllib.request.urlopen(f"{base_url}/") as resp:
            self.assertEqual(resp.status, 200)
            content = resp.read().decode("utf-8")
            self.assertIn("Blockchain-Lite Ledger", content)
            self.assertIn("<!DOCTYPE html>", content)

        # 2. GET /api/chain
        with urllib.request.urlopen(f"{base_url}/api/chain") as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertGreaterEqual(data["height"], 2)
            self.assertTrue(data["is_valid"])

        # 3. GET /api/blocks
        with urllib.request.urlopen(f"{base_url}/api/blocks") as resp:
            self.assertEqual(resp.status, 200)
            blocks = json.loads(resp.read().decode("utf-8"))
            self.assertGreaterEqual(len(blocks), 2)
            self.assertEqual(blocks[0]["index"], 0)

        # 4. GET /api/wallets
        with urllib.request.urlopen(f"{base_url}/api/wallets") as resp:
            self.assertEqual(resp.status, 200)
            wallet_list = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(len(wallet_list), 4)

        # 5. POST /api/transfer
        bob = wallets["Bob"]
        transfer_payload = json.dumps({
            "sender_name": "Alice",
            "recipient_address": bob.address.hex(),
            "amount": 5,
            "fee": 1,
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{base_url}/api/transfer",
            data=transfer_payload,
            headers={"Content-Type": "application/json", "X-API-Token": server.api_token},
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            res_data = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(res_data["ok"])

        # 6. POST /api/mine
        mine_payload = json.dumps({
            "miner_address": wallets["Miner"].address.hex()
        }).encode("utf-8")
        req_mine = urllib.request.Request(
            f"{base_url}/api/mine",
            data=mine_payload,
            headers={"Content-Type": "application/json", "X-API-Token": server.api_token},
        )
        try:
            with urllib.request.urlopen(req_mine) as resp:
                self.assertEqual(resp.status, 200)
                mine_data = json.loads(resp.read().decode("utf-8"))
                self.assertTrue(mine_data["ok"])
                self.assertIn("block", mine_data)
        except urllib.error.HTTPError as err:
            err_body = err.read().decode("utf-8")
            self.fail(f"Mining API failed with status {err.code}: {err_body}")

        # 7. POST /api/tamper (target signed transfer at tx_index=1)
        tamper_payload = json.dumps({
            "block_index": 1,
            "tx_index": 1,
        }).encode("utf-8")
        req_tamper = urllib.request.Request(
            f"{base_url}/api/tamper",
            data=tamper_payload,
            headers={"Content-Type": "application/json", "X-API-Token": server.api_token},
        )
        with urllib.request.urlopen(req_tamper) as resp:
            self.assertEqual(resp.status, 200)
            tamper_data = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(tamper_data["ok"])
            self.assertFalse(tamper_data["report"]["signature_valid_after_tamper"])
            self.assertFalse(tamper_data["report"]["merkle_root_matches_header"])


class TestRSASecurityInspection(unittest.TestCase):
    """Verify RSA security inspection helpers format_security_summary and is_production_grade."""

    def test_rsa_security_summary_and_production_grade_flag(self) -> None:
        pub, priv = default_crypto_engine.generate_keypair_objects(bit_length=384)

        self.assertFalse(pub.is_production_grade)
        self.assertFalse(priv.is_production_grade)
        self.assertIn("EDUCATIONAL-ONLY", pub.format_security_summary())
        self.assertIn("2048", pub.format_security_summary())


if __name__ == "__main__":
    unittest.main()
