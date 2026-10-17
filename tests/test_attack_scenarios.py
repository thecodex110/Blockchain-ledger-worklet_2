"""
Attack Scenarios (viva demo): each test replays a verified audit exploit and shows it fails.

Run just this module:   python -m unittest -v tests.test_attack_scenarios

| Defect | Attack                                                        | Test(s)                                                   |
| :----- | :------------------------------------------------------------ | :-------------------------------------------------------- |
| D1     | Replace an honest chain with cheap difficulty-0 blocks        | test_d1_difficulty_zero_attacker_chain_rejected_by_resolve_forks, test_d1_append_mined_block_rejects_wrong_difficulty |
| D1     | (guard) honest retargeting and longer honest forks still work | test_d1_honest_retargeting_still_validates_and_is_enforced, test_d1_longer_valid_fork_still_wins_by_cumulative_work |
| D2     | Forge a .bclt file minting 10^15 coins with a matching header | test_d2_forged_reward_file_rejected, test_d2_header_difficulty_disagreeing_with_protocol_rejected |
| D3     | Same miner mining twice in one second -> coinbase collision   | test_d3_repeated_same_second_mining_by_one_miner_succeeds, test_coinbase_height_must_match_block_index |
| D4     | Dashboard Merkle-proof route crashed                          | test_d4_merkle_proof_endpoint_for_1_2_3_tx_blocks          |
| D5     | Cross-site "simple request" spends a custodial demo wallet    | test_d5_post_without_or_with_wrong_token_is_rejected, test_d5_text_plain_simple_request_rejected, test_d5_no_wildcard_cors_header |
| D6     | Garbage Content-Length / leaked exception text / mining DoS   | test_d6_bad_content_length_handled, test_d6_unexpected_errors_return_generic_500, test_d6_reads_stay_responsive_while_dashboard_mines |
| D8     | Blocks timestamped in the far past or future                  | test_d8_block_timestamps_far_past_or_future_rejected       |

Every scenario test failed on the pre-fix code (verified when it was written) and passes now.
"""

from __future__ import annotations

import http.client
import json
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

from blockchain_lite.crypto.asymmetric import MIN_RSA_MODULUS_BITS, RSACryptoEngine
from blockchain_lite.interfaces import MerkleProof, MerkleProofStep, ValidationError
from blockchain_lite.ledger.chain import BlockchainLedger
from blockchain_lite.ledger.merkle import MerkleTree
from blockchain_lite.ledger.persistence import ChainPersistence
from blockchain_lite.ledger.pow import ProofOfWorkMiner
from blockchain_lite.models.transaction import Transaction
from blockchain_lite.network.web_dashboard import WebDashboardServer
from blockchain_lite.wallet.wallet import Wallet

T0 = 1700000000


def _coinbase(addr: bytes, amount: int, height: int) -> Transaction:
    # Coinbase commits the block height in its timestamp field (BIP34-style).
    return Transaction.create_coinbase(recipient_address=addr, amount=amount, timestamp=height)


class TestConsensusEnforcement(unittest.TestCase):
    """D1 + D8: difficulty schedule and timestamp rules are enforced, not self-declared."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = RSACryptoEngine()
        cls.alice = Wallet.generate("Alice", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=cls.engine)
        cls.mallory = Wallet.generate("Mallory", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=cls.engine)

    def _honest_ledger(self, difficulty: int = 6) -> BlockchainLedger:
        ledger = BlockchainLedger(difficulty=difficulty, block_reward=50, crypto_engine=self.engine)
        ledger.create_genesis_block([(self.alice.address, 1000)], timestamp=T0)
        ledger.mine_pending_transactions(miner_address=self.alice.address, timestamp=T0 + 60)
        return ledger

    def _cheap_fork(self, genesis, length: int, difficulty: int = 0):
        miner = ProofOfWorkMiner()
        blocks = [genesis]
        for h in range(1, length):
            blocks.append(miner.mine_block(
                index=h,
                previous_hash=blocks[-1].block_hash,
                transactions=[_coinbase(self.mallory.address, 50, h)],
                difficulty=difficulty,
                timestamp=T0 + 10 * h,
            ))
        return blocks

    def test_d1_difficulty_zero_attacker_chain_rejected_by_resolve_forks(self) -> None:
        honest = self._honest_ledger()
        tip_before = honest.tip.block_hash
        attacker = self._cheap_fork(honest.blocks[0], length=6, difficulty=0)

        outcome = honest.resolve_forks([attacker])

        self.assertFalse(outcome.switched_chain)
        self.assertEqual(outcome.rejected_candidates_count, 1)
        self.assertEqual(honest.tip.block_hash, tip_before)
        self.assertEqual(honest.get_balance(self.mallory.address), 0)

    def test_d1_append_mined_block_rejects_wrong_difficulty(self) -> None:
        honest = self._honest_ledger()
        miner = ProofOfWorkMiner()
        for bad_diff in (0, honest.difficulty + 1):
            block = miner.mine_block(
                index=2,
                previous_hash=honest.tip.block_hash,
                transactions=[_coinbase(self.mallory.address, 50, 2)],
                difficulty=bad_diff,
                timestamp=T0 + 120,
            )
            with self.assertRaises(ValidationError):
                honest.append_mined_block(block)
        self.assertEqual(honest.height, 2)

    def test_d1_longer_valid_fork_still_wins_by_cumulative_work(self) -> None:
        # Equal-difficulty, longer honest fork still wins (more work).
        honest = self._honest_ledger(difficulty=4)
        longer = BlockchainLedger(difficulty=4, block_reward=50, crypto_engine=self.engine)
        longer.load_verified_chain(honest.blocks[:1])
        for i in range(2):
            longer.mine_pending_transactions(miner_address=self.mallory.address, timestamp=T0 + 100 + i)
        outcome = honest.resolve_forks([longer.blocks])
        self.assertTrue(outcome.switched_chain)
        self.assertEqual(outcome.winning_cumulative_work, 3 * (1 << 4))

    def test_d1_honest_retargeting_still_validates_and_is_enforced(self) -> None:
        params = dict(difficulty=3, retarget_interval=2, target_block_time_seconds=10.0,
                      min_difficulty=1, max_difficulty=8)
        ledger = BlockchainLedger(crypto_engine=self.engine, **params)
        ledger.create_genesis_block([(self.alice.address, 100)], timestamp=T0)
        for i in range(1, 5):
            ledger.mine_pending_transactions(miner_address=self.alice.address, timestamp=T0 + i)
        diffs = [b.difficulty for b in ledger.blocks]
        self.assertEqual(diffs, [3, 3, 4, 4, 5])

        # calculate_next_difficulty is a pure query.
        self.assertEqual(ledger.calculate_next_difficulty(), ledger.calculate_next_difficulty())

        replica = BlockchainLedger(crypto_engine=self.engine, **params)
        replica.load_verified_chain(ledger.blocks)
        self.assertEqual(replica.tip.block_hash, ledger.tip.block_hash)

        # Same chain under fixed difficulty 3 is invalid (blocks 2..4 claim the wrong difficulty).
        fixed = BlockchainLedger(difficulty=3, crypto_engine=self.engine)
        with self.assertRaises(ValidationError):
            fixed.load_verified_chain(ledger.blocks)

    def test_d8_block_timestamps_far_past_or_future_rejected(self) -> None:
        honest = self._honest_ledger(difficulty=2)
        miner = ProofOfWorkMiner()
        far_future = int(time.time()) + 3 * 3600
        for ts in (5, far_future, 2 ** 63):
            block = miner.mine_block(
                index=2,
                previous_hash=honest.tip.block_hash,
                transactions=[_coinbase(self.mallory.address, 50, 2)],
                difficulty=2,
                timestamp=ts,
            )
            with self.assertRaises(ValidationError, msg=f"timestamp={ts}"):
                honest.append_mined_block(block)
        self.assertEqual(honest.height, 2)

    def test_coinbase_height_must_match_block_index(self) -> None:
        honest = self._honest_ledger(difficulty=2)
        block = ProofOfWorkMiner().mine_block(
            index=2,
            previous_hash=honest.tip.block_hash,
            transactions=[_coinbase(self.mallory.address, 50, 7)],
            difficulty=2,
            timestamp=T0 + 120,
        )
        with self.assertRaises(ValidationError):
            honest.append_mined_block(block)


class TestCoinbaseUniqueness(unittest.TestCase):
    """D3: same miner, same reward, same second must not collide."""

    def test_d3_repeated_same_second_mining_by_one_miner_succeeds(self) -> None:
        miner = Wallet.generate("Miner", bit_length=MIN_RSA_MODULUS_BITS)
        ledger = BlockchainLedger(difficulty=1, block_reward=50)
        ledger.create_genesis_block([(miner.address, 10)], timestamp=T0)
        for _ in range(3):
            ledger.mine_pending_transactions(miner_address=miner.address, timestamp=T0 + 5)
        ledger.mine_pending_transactions(miner_address=miner.address)
        ledger.mine_pending_transactions(miner_address=miner.address)
        self.assertEqual(ledger.height, 6)
        self.assertEqual(ledger.get_balance(miner.address), 10 + 5 * 50)
        self.assertTrue(ledger.validate_full_chain().is_valid)


class TestPersistenceTrustsProtocolNotFile(unittest.TestCase):
    """D2: header block_reward / difficulty are untrusted."""

    def test_d2_forged_reward_file_rejected(self) -> None:
        mallory = Wallet.generate("Mallory", bit_length=MIN_RSA_MODULUS_BITS)
        ledger = BlockchainLedger()  # protocol defaults
        ledger.create_genesis_block([(mallory.address, 1)], timestamp=T0)
        genesis_hash = ledger.genesis_hash
        forged = ProofOfWorkMiner().mine_block(
            index=1,
            previous_hash=genesis_hash,
            transactions=[_coinbase(mallory.address, 10 ** 15, 1)],
            difficulty=ledger.difficulty,
            timestamp=T0 + 60,
        )
        persistence = ChainPersistence()
        raw = persistence.serialize_chain(
            [ledger.blocks[0], forged], difficulty=ledger.difficulty, block_reward=10 ** 15
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "forged.bclt"
            path.write_bytes(raw)
            with self.assertRaises(ValidationError):
                persistence.load_ledger(path, expected_genesis_hash=genesis_hash)

    def test_d2_header_difficulty_disagreeing_with_protocol_rejected(self) -> None:
        w = Wallet.generate("W", bit_length=MIN_RSA_MODULUS_BITS)
        cheap = BlockchainLedger(difficulty=0)
        cheap.create_genesis_block([(w.address, 1)], timestamp=T0)
        persistence = ChainPersistence()  # default protocol difficulty is not 0
        with tempfile.TemporaryDirectory() as tmp:
            path = persistence.save_ledger(cheap, Path(tmp) / "cheap.bclt")
            with self.assertRaises(ValidationError):
                persistence.load_ledger(path)


class TestDashboardHardening(unittest.TestCase):
    """D4 (Merkle route), D5 (auth/CSRF/CORS), D6 (body handling, errors)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.alice = Wallet.generate("Alice", bit_length=MIN_RSA_MODULUS_BITS)
        cls.bob = Wallet.generate("Bob", bit_length=MIN_RSA_MODULUS_BITS)
        ledger = BlockchainLedger(difficulty=1, block_reward=50)
        ledger.create_genesis_block([(cls.alice.address, 1000)], timestamp=T0)  # 1-tx block
        tx = cls.alice.create_signed_transfer(
            cls.bob.address, 10, ledger.get_spendable_utxos(cls.alice.address), fee=1, timestamp=T0 + 1)
        ledger.submit_transaction(tx)
        ledger.mine_pending_transactions(miner_address=cls.bob.address, timestamp=T0 + 10)  # 2-tx block
        tx_a = cls.alice.create_signed_transfer(
            cls.bob.address, 5, ledger.get_spendable_utxos(cls.alice.address), fee=0, timestamp=T0 + 11)
        ledger.submit_transaction(tx_a)
        tx_b = cls.bob.create_signed_transfer(
            cls.alice.address, 3, ledger.get_spendable_utxos(cls.bob.address), fee=0, timestamp=T0 + 12)
        ledger.submit_transaction(tx_b)
        ledger.mine_pending_transactions(miner_address=cls.bob.address, timestamp=T0 + 20)  # 3-tx block
        cls.ledger = ledger
        cls.server = WebDashboardServer(ledger=ledger, named_wallets={"Alice": cls.alice}, port=0)
        cls.server.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.stop()

    def _raw(self, method: str, path: str, body: bytes = b"", headers=None):
        conn = http.client.HTTPConnection(self.server.host, self.server.bound_port, timeout=5)
        try:
            conn.putrequest(method, path)
            for k, v in (headers or {}).items():
                conn.putheader(k, v)
            conn.endheaders()
            if body:
                conn.send(body)
            resp = conn.getresponse()
            return resp.status, resp.read().decode("utf-8", "replace")
        finally:
            conn.close()

    def _post(self, path: str, payload: dict, token: str | None = "auto", ctype: str = "application/json"):
        body = json.dumps(payload).encode()
        headers = {"Content-Type": ctype, "Content-Length": str(len(body))}
        if token == "auto":
            token = self.server.api_token
        if token is not None:
            headers["X-API-Token"] = token
        return self._raw("POST", path, body, headers)

    def test_d4_merkle_proof_endpoint_for_1_2_3_tx_blocks(self) -> None:
        for block in self.ledger.blocks[:3]:  # later tests may mine more blocks
            for tx in block.transactions:
                url = f"{self.server.url}/api/merkle_proof?block={block.index}&tx_id={tx.tx_id_hex}"
                with urllib.request.urlopen(url, timeout=5) as resp:
                    data = json.loads(resp.read())
                self.assertTrue(data["ok"])
                p = data["proof"]
                self.assertTrue(p["is_valid"])
                self.assertEqual(p["tx_id"], tx.tx_id_hex)
                self.assertEqual(p["merkle_root"], block.merkle_root_hex)
                # Independently re-verify the JSON proof against the header root.
                proof = MerkleProof(
                    tx_id=bytes.fromhex(p["tx_id"]),
                    tx_index=block.transactions.index(tx),
                    merkle_root=bytes.fromhex(p["merkle_root"]),
                    steps=tuple(MerkleProofStep(bytes.fromhex(s["sibling_hash"]), s["direction"]) for s in p["path"]),
                )
                self.assertTrue(MerkleTree.verify_proof(proof, expected_merkle_root=block.merkle_root))
        self.assertEqual([len(b.transactions) for b in self.ledger.blocks[:3]], [1, 2, 3])

    def test_d5_post_without_or_with_wrong_token_is_rejected(self) -> None:
        payload = {"sender_name": "Alice", "recipient_address": self.bob.address.hex(), "amount": 1, "fee": 0}
        status, _ = self._post("/api/transfer", payload, token=None)
        self.assertIn(status, (401, 403))
        status, _ = self._post("/api/transfer", payload, token="wrong")
        self.assertIn(status, (401, 403))
        self.assertEqual(len(self.ledger.mempool), 0)

    def test_d5_text_plain_simple_request_rejected(self) -> None:
        payload = {"sender_name": "Alice", "recipient_address": self.bob.address.hex(), "amount": 1, "fee": 0}
        status, _ = self._post("/api/transfer", payload, ctype="text/plain")
        self.assertEqual(status, 415)
        self.assertEqual(len(self.ledger.mempool), 0)

    def test_d5_no_wildcard_cors_header(self) -> None:
        with urllib.request.urlopen(f"{self.server.url}/api/chain", timeout=5) as resp:
            self.assertIsNone(resp.headers.get("Access-Control-Allow-Origin"))

    def test_d6_bad_content_length_handled(self) -> None:
        base = {"Content-Type": "application/json", "X-API-Token": self.server.api_token}
        for cl, expected in (("abc", 400), ("-5", 400), (str(10 * 1024 * 1024), 413)):
            status, body = self._raw("POST", "/api/tamper", b"", {**base, "Content-Length": cl})
            self.assertEqual(status, expected, f"Content-Length={cl}")
            self.assertNotIn("Traceback", body)

    def test_d6_reads_stay_responsive_while_dashboard_mines(self) -> None:
        miner = self.ledger._miner
        original = miner.mine_block_with_stats
        mining_started = threading.Event()

        def slow_mine(*args, **kwargs):
            mining_started.set()
            time.sleep(1.5)  # stands in for a long nonce search
            return original(*args, **kwargs)

        miner.mine_block_with_stats = slow_mine
        try:
            result = {}
            worker = threading.Thread(target=lambda: result.update(
                mine=self._post("/api/mine", {"miner_address": self.bob.address.hex()})))
            worker.start()
            self.assertTrue(mining_started.wait(5))
            t0 = time.perf_counter()
            status, body = self._raw("GET", "/api/chain")
            elapsed = time.perf_counter() - t0
            worker.join(10)
        finally:
            miner.mine_block_with_stats = original
        self.assertEqual(status, 200)
        self.assertLess(elapsed, 1.0, "GET /api/chain blocked behind mining")
        self.assertEqual(result["mine"][0], 200)

    def test_logs_record_events_but_never_the_api_token(self) -> None:
        with self.assertLogs("blockchain_lite.network.web_dashboard", level="INFO") as cm:
            self._post("/api/mine", {"miner_address": self.bob.address.hex()}, token="not-the-token")
            self._post("/api/mine", {"miner_address": self.bob.address.hex()})
        out = "\n".join(cm.output)
        self.assertIn("Rejected POST /api/mine: 401", out)
        self.assertIn("Mined block #", out)
        self.assertNotIn(self.server.api_token, out)
        self.assertNotIn("not-the-token", out)

    def test_d6_unexpected_errors_return_generic_500(self) -> None:
        original = self.ledger.get_balance

        def boom(_addr):
            raise RuntimeError("internal-detail-should-not-leak")

        self.ledger.get_balance = boom  # type: ignore[method-assign]
        try:
            status, body = self._raw("GET", "/api/wallets")
        finally:
            self.ledger.get_balance = original  # type: ignore[method-assign]
        self.assertEqual(status, 500)
        self.assertNotIn("internal-detail-should-not-leak", body)


if __name__ == "__main__":
    unittest.main()
