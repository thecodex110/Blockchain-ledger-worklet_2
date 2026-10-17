"""
Phase 11: optional hashlib-backed SHA-256 (audit finding D10).

The fast backend must be bit-identical to the from-scratch `BitLevelSHA256`, so a
chain's bytes never depend on which backend mined or validated it.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from blockchain_lite.crypto.asymmetric import MIN_RSA_MODULUS_BITS
from blockchain_lite.crypto.fast_hash import HashlibSHA256
from blockchain_lite.crypto.hashing import BitLevelSHA256, default_hasher
from blockchain_lite.ledger.chain import BlockchainLedger
from blockchain_lite.ledger.merkle import MerkleTree
from blockchain_lite.ledger.persistence import ChainPersistence
from blockchain_lite.ledger.pow import ProofOfWorkMiner
from blockchain_lite.models.transaction import Transaction
from blockchain_lite.wallet.wallet import Wallet

FAST = HashlibSHA256()
PURE = default_hasher
ROOT = Path(__file__).resolve().parent.parent
T0 = 1700000000


class TestDigestEquivalence(unittest.TestCase):
    def test_known_answer_vectors(self) -> None:
        # FIPS 180-2 published test vectors.
        self.assertEqual(FAST.hash_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(FAST.hash_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(
            FAST.hash_hex(b"a" * 1_000_000),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        )

    def test_padding_boundaries_match_pure_python(self) -> None:
        for n in (0, 3, 55, 56, 63, 64, 65, 119, 120, 128, 1000):
            data = bytes((i * 7 + n) % 256 for i in range(n))
            self.assertEqual(FAST.hash_bytes(data), PURE.hash_bytes(data), f"len={n}")
            self.assertEqual(FAST.hash_hex(data), PURE.hash_hex(data))

    @unittest.skipUnless(os.environ.get("BLOCKCHAIN_LITE_SLOW_TESTS") == "1",
                         "1 MB pure-Python hash takes ~9 s; set BLOCKCHAIN_LITE_SLOW_TESTS=1")
    def test_one_megabyte_matches_pure_python(self) -> None:
        data = b"a" * 1_000_000
        self.assertEqual(FAST.hash_bytes(data), PURE.hash_bytes(data))

    def test_interface_and_avalanche_behave_identically(self) -> None:
        self.assertIsInstance(FAST, BitLevelSHA256)
        self.assertEqual(FAST.digest_size, 32)
        self.assertEqual(FAST.analyze_avalanche(b"abc", b"abd"), PURE.analyze_avalanche(b"abc", b"abd"))


class TestChainBytesIndependentOfHasher(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.alice = Wallet.generate("A", bit_length=MIN_RSA_MODULUS_BITS)
        cls.bob = Wallet.generate("B", bit_length=MIN_RSA_MODULUS_BITS)

    def _mine_chain(self, hasher) -> BlockchainLedger:
        ledger = BlockchainLedger(difficulty=6, hasher=hasher)
        ledger.create_genesis_block([(self.alice.address, 100)], timestamp=T0)
        tx = self.alice.create_signed_transfer(
            self.bob.address, 30, ledger.get_spendable_utxos(self.alice.address), fee=2, timestamp=T0 + 1)
        ledger.submit_transaction(tx)
        ledger.mine_pending_transactions(miner_address=self.bob.address, timestamp=T0 + 10)
        ledger.mine_pending_transactions(miner_address=self.alice.address, timestamp=T0 + 20)
        return ledger

    def test_merkle_roots_and_block_hashes_identical(self) -> None:
        txs = [Transaction.create_coinbase(self.alice.address, 50 + i, timestamp=i) for i in range(5)]
        self.assertEqual(MerkleTree.from_transactions(txs, hasher=FAST).root,
                         MerkleTree.from_transactions(txs, hasher=PURE).root)
        args = dict(index=1, previous_hash=b"\x11" * 32, transactions=txs, difficulty=6, timestamp=T0)
        fast_block = ProofOfWorkMiner(hasher=FAST).mine_block(**args)
        pure_block = ProofOfWorkMiner(hasher=PURE).mine_block(**args)
        self.assertEqual(fast_block.to_bytes(), pure_block.to_bytes())
        self.assertEqual(fast_block.compute_header_hash(hasher=PURE), fast_block.block_hash)

    def test_chain_mined_with_each_hasher_validates_with_the_other(self) -> None:
        for miner_hasher, checker_hasher in ((FAST, PURE), (PURE, FAST)):
            mined = self._mine_chain(miner_hasher)
            replica = BlockchainLedger(difficulty=6, hasher=checker_hasher)
            replica.load_verified_chain(mined.blocks)
            self.assertEqual(replica.tip.block_hash, mined.tip.block_hash)
            self.assertEqual(replica.get_balance(self.bob.address), mined.get_balance(self.bob.address))

    def test_persisted_file_is_byte_identical_across_hashers(self) -> None:
        mined = self._mine_chain(FAST)
        with tempfile.TemporaryDirectory() as tmp:
            fast_path = ChainPersistence(hasher=FAST, params=mined.params).save_ledger(mined, Path(tmp) / "f.bclt")
            reloaded = ChainPersistence(hasher=PURE, params=mined.params).load_ledger(fast_path)
            pure_path = ChainPersistence(hasher=PURE, params=mined.params).save_ledger(reloaded, Path(tmp) / "p.bclt")
            self.assertEqual(fast_path.read_bytes(), pure_path.read_bytes())


class TestFastHashIsOptIn(unittest.TestCase):
    def test_default_import_graph_never_loads_fast_hash(self) -> None:
        code = (
            "import sys, pkgutil, importlib, blockchain_lite\n"
            "skip = {'blockchain_lite.crypto.fast_hash'}\n"
            "for m in pkgutil.walk_packages(blockchain_lite.__path__, 'blockchain_lite.'):\n"
            "    if m.name not in skip: importlib.import_module(m.name)\n"
            "print('blockchain_lite.crypto.fast_hash' in sys.modules)\n"
        )
        out = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), "False")

    def test_benchmark_reports_both_hashers(self) -> None:
        from blockchain_lite.benchmarks.pow_benchmark import compare_hasher_throughput
        rows = compare_hasher_throughput(seconds=0.2)
        names = [r[0] for r in rows]
        self.assertEqual(names, ["BitLevelSHA256", "HashlibSHA256"])
        self.assertTrue(all(hps > 0 for _, hps in rows))

    def test_dashboard_demo_ledger_accepts_hasher(self) -> None:
        from blockchain_lite.network.web_dashboard import create_demo_ledger_and_wallets
        ledger, _ = create_demo_ledger_and_wallets(hasher=FAST)
        self.assertIs(ledger._hasher, FAST)
        replica = BlockchainLedger(difficulty=ledger.difficulty, block_reward=ledger.block_reward)
        replica.load_verified_chain(ledger.blocks)  # validated by the pure-Python hasher


if __name__ == "__main__":
    unittest.main()
