"""
Phase 9 Core-Engineering Suite (audit findings D7, D9, D11, D14-Merkle).

Cheap reads, non-blocking mining, authenticated mining RPC, incremental mempool,
one-pass failure reporting, and latent-quality fixes.
"""

from __future__ import annotations

import importlib
import inspect
import re
import threading
import typing
import unittest
from pathlib import Path

import blockchain_lite
from blockchain_lite.crypto.asymmetric import MIN_RSA_MODULUS_BITS, RSACryptoEngine, RSAPublicKey
from blockchain_lite.interfaces import DoubleSpendError, ValidationError
from blockchain_lite.ledger.chain import BlockchainLedger
from blockchain_lite.ledger.merkle import MerkleTree
from blockchain_lite.ledger.pow import ProofOfWorkMiner
from blockchain_lite.models.block import Block
from blockchain_lite.models.transaction import Transaction
from blockchain_lite.network.client import WalletClient
from blockchain_lite.network.server import InMemoryTransport, LedgerServerDispatcher
from blockchain_lite.network.transport import ClientTransport, NetworkRPCError
from blockchain_lite.wallet.wallet import Wallet

T0 = 1700000000
ENGINE = RSACryptoEngine()


class CountingEngine(RSACryptoEngine):
    def __init__(self) -> None:
        super().__init__()
        self.verify_calls = 0

    def verify(self, *args, **kwargs):  # type: ignore[override]
        self.verify_calls += 1
        return super().verify(*args, **kwargs)


def _count_calls(obj, name):
    counter = {"n": 0}
    original = getattr(obj, name)

    def wrapper(*args, **kwargs):
        counter["n"] += 1
        return original(*args, **kwargs)

    setattr(obj, name, wrapper)
    return counter


class TestCheapReads(unittest.TestCase):
    """D7: chain-health queries are cached per tip."""

    def setUp(self) -> None:
        self.w = Wallet.generate("W", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=ENGINE)
        self.ledger = BlockchainLedger(difficulty=1, crypto_engine=ENGINE)
        self.ledger.create_genesis_block([(self.w.address, 100)], timestamp=T0)

    def test_get_chain_info_does_not_revalidate_every_call(self) -> None:
        spy = _count_calls(self.ledger.validator, "validate_chain")
        rpc = InMemoryTransport(LedgerServerDispatcher(self.ledger))
        for _ in range(5):
            self.assertTrue(rpc.send_request("get_chain_info", {})["is_valid"])
        self.assertEqual(spy["n"], 1)

        self.ledger.mine_pending_transactions(miner_address=self.w.address, timestamp=T0 + 1)
        for _ in range(3):
            info = rpc.send_request("get_chain_info", {})
        self.assertEqual(info["height"], 2)
        self.assertEqual(spy["n"], 2)

        rpc.send_request("get_chain_info", {"full": True})
        self.assertEqual(spy["n"], 3)

    def test_reads_are_not_blocked_while_mining(self) -> None:
        dispatcher = LedgerServerDispatcher(self.ledger, mine_token="t0k")
        miner = self.ledger._miner
        original = miner.mine_block_with_stats
        reader_blocked = []

        def slow_mine(*args, **kwargs):
            def read():
                dispatcher.handle_request({"method": "get_balance", "params": {"address_hex": self.w.address.hex()}})
                self.ledger.get_balance(self.w.address)
            t = threading.Thread(target=read)
            t.start()
            t.join(timeout=3.0)
            reader_blocked.append(t.is_alive())
            return original(*args, **kwargs)

        miner.mine_block_with_stats = slow_mine
        resp = dispatcher.handle_request({
            "method": "mine_block",
            "params": {"miner_address_hex": self.w.address.hex(), "auth_token": "t0k"},
        })
        self.assertTrue(resp["ok"], resp)
        self.assertEqual(reader_blocked, [False])


class TestMiningRPCPolicy(unittest.TestCase):
    """D7/D10: mining RPC needs a token; client timestamps need explicit opt-in."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.w = Wallet.generate("W", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=ENGINE)

    def _ledger(self) -> BlockchainLedger:
        ledger = BlockchainLedger(difficulty=1, crypto_engine=ENGINE)
        ledger.create_genesis_block([(self.w.address, 100)], timestamp=T0)
        return ledger

    def _mine(self, dispatcher, **params):
        params.setdefault("miner_address_hex", self.w.address.hex())
        return dispatcher.handle_request({"method": "mine_block", "params": params})

    def test_mine_block_requires_configured_token(self) -> None:
        self.assertFalse(self._mine(LedgerServerDispatcher(self._ledger()))["ok"])
        d = LedgerServerDispatcher(self._ledger(), mine_token="s3cret")
        self.assertFalse(self._mine(d)["ok"])
        self.assertFalse(self._mine(d, auth_token="wrong")["ok"])
        self.assertTrue(self._mine(d, auth_token="s3cret")["ok"])

    def test_rpc_logs_record_events_but_never_the_token(self) -> None:
        d = LedgerServerDispatcher(self._ledger(), mine_token="s3cret-token-value")
        with self.assertLogs("blockchain_lite.network.server", level="INFO") as cm:
            self._mine(d, auth_token="wrong-token-value")
            self._mine(d, auth_token="s3cret-token-value")
        out = "\n".join(cm.output)
        self.assertIn("Rejected RPC mine_block: ValidationError", out)
        self.assertIn("Mined block #1", out)
        self.assertNotIn("s3cret-token-value", out)
        self.assertNotIn("wrong-token-value", out)

    def test_client_timestamp_requires_opt_in(self) -> None:
        d = LedgerServerDispatcher(self._ledger(), mine_token="k")
        resp = self._mine(d, auth_token="k", timestamp=T0 + 5)
        self.assertFalse(resp["ok"])
        d2 = LedgerServerDispatcher(self._ledger(), mine_token="k", allow_client_timestamp=True)
        self.assertTrue(self._mine(d2, auth_token="k", timestamp=T0 + 5)["ok"])


class TestIncrementalMempool(unittest.TestCase):
    """D9: each submission validates only the new tx; caps are enforced."""

    def setUp(self) -> None:
        self.engine = CountingEngine()
        self.alice = Wallet.generate("A", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=self.engine)
        self.bob = Wallet.generate("B", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=self.engine)

    def _ledger(self, **kw) -> BlockchainLedger:
        ledger = BlockchainLedger(difficulty=1, crypto_engine=self.engine, **kw)
        ledger.create_genesis_block([(self.alice.address, 10)] * 8, timestamp=T0)
        return ledger

    def _txs(self, ledger, n, fee=0):
        utxos = ledger.get_spendable_utxos(self.alice.address)
        return [self.alice.create_signed_transfer(self.bob.address, 5, [u], fee=fee, timestamp=T0 + 1)
                for u in utxos[:n]]

    def test_submission_cost_is_linear_not_quadratic(self) -> None:
        ledger = self._ledger()
        txs = self._txs(ledger, 6)
        self.engine.verify_calls = 0
        for tx in txs:
            ledger.submit_transaction(tx)
        self.assertEqual(self.engine.verify_calls, 6)  # one signature check per new tx
        self.assertEqual(len(ledger.mempool), 6)
        ledger.submit_transaction(txs[0])  # idempotent duplicate, no re-verification
        self.assertEqual(len(ledger.mempool), 6)
        self.assertEqual(self.engine.verify_calls, 6)

    def test_mempool_double_spend_still_rejected_and_pruned_after_block(self) -> None:
        ledger = self._ledger()
        utxo = ledger.get_spendable_utxos(self.alice.address)[0]
        first = self.alice.create_signed_transfer(self.bob.address, 5, [utxo], timestamp=T0 + 1)
        second = self.alice.create_signed_transfer(self.bob.address, 6, [utxo], timestamp=T0 + 2)
        ledger.submit_transaction(first)
        with self.assertRaises(DoubleSpendError):
            ledger.submit_transaction(second)
        ledger.mine_pending_transactions(miner_address=self.bob.address, timestamp=T0 + 3)
        self.assertEqual(len(ledger.mempool), 0)
        with self.assertRaises(DoubleSpendError):
            ledger.submit_transaction(second)  # input now spent on-chain

    def test_max_mempool_size_and_min_fee(self) -> None:
        ledger = self._ledger(max_mempool_size=2)
        txs = self._txs(ledger, 3)
        ledger.submit_transaction(txs[0])
        ledger.submit_transaction(txs[1])
        with self.assertRaises(ValidationError):
            ledger.submit_transaction(txs[2])

        fee_ledger = self._ledger(min_fee=2)
        cheap, = self._txs(fee_ledger, 1, fee=1)
        with self.assertRaises(ValidationError):
            fee_ledger.submit_transaction(cheap)
        ok, = self._txs(fee_ledger, 1, fee=2)
        fee_ledger.submit_transaction(ok)


class TestOnePassValidation(unittest.TestCase):
    """D11: validate_chain reports the failing index without re-validating prefixes."""

    def test_failed_block_index_found_in_one_pass(self) -> None:
        w = Wallet.generate("W", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=ENGINE)
        ledger = BlockchainLedger(difficulty=1, crypto_engine=ENGINE)
        ledger.create_genesis_block([(w.address, 100)], timestamp=T0)
        for i in range(4):
            ledger.mine_pending_transactions(miner_address=w.address, timestamp=T0 + i + 1)
        blocks = list(ledger.blocks)
        b = blocks[3]
        blocks[3] = Block(index=b.index, previous_hash=b.previous_hash, merkle_root=b.merkle_root,
                          timestamp=b.timestamp, difficulty=b.difficulty, nonce=b.nonce + 1,
                          transactions=b.transactions, block_hash=b.block_hash)
        spy = _count_calls(ledger.validator, "validate_chain_or_raise")
        report = ledger.validator.validate_chain(blocks)
        self.assertFalse(report.is_valid)
        self.assertEqual(report.failed_block_index, 3)
        self.assertEqual(spy["n"], 1)


class TestLatentQualityFixes(unittest.TestCase):
    """D11: NameErrors hidden by postponed annotations, duplicate members, asserts, version drift."""

    def test_type_hints_resolve_in_ledger_modules(self) -> None:
        for mod_name in ("ledger.validator", "ledger.merkle", "ledger.chain", "ledger.consensus",
                         "ledger.persistence", "ledger.utxo", "ledger.pow", "network.web_dashboard",
                         "network.server", "network.client", "benchmarks.pow_benchmark"):
            mod = importlib.import_module(f"blockchain_lite.{mod_name}")
            for _, obj in inspect.getmembers(mod):
                if getattr(obj, "__module__", None) != mod.__name__:
                    continue
                targets = [obj] + ([m for _, m in inspect.getmembers(obj, inspect.isfunction)]
                                   if inspect.isclass(obj) else [])
                for target in targets:
                    if callable(target):
                        typing.get_type_hints(target)  # raises NameError on a missing import

    def test_rsa_public_key_bit_length_defined_once(self) -> None:
        self.assertEqual(inspect.getsource(RSAPublicKey).count("def bit_length"), 1)

    def test_send_funds_tx_id_mismatch_raises_protocol_error(self) -> None:
        w = Wallet.generate("W", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=ENGINE)

        class LyingTransport(ClientTransport):
            def send_request(self, method, params):
                if method == "get_utxos":
                    return {"utxos": [{"tx_id": "11" * 32, "output_index": 0, "amount": 50,
                                       "recipient_address": w.address.hex()}]}
                return {"tx_id_hex": "00" * 32}

        client = WalletClient(w, LyingTransport())
        with self.assertRaises(NetworkRPCError):
            client.send_funds(recipient_address=b"\x22" * 32, amount=10)

    def test_package_version_matches_pyproject(self) -> None:
        root = Path(blockchain_lite.__file__).resolve().parent.parent
        text = (root / "pyproject.toml").read_text(encoding="utf-8")
        static = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
        if static:
            self.assertEqual(blockchain_lite.__version__, static.group(1))
        else:
            self.assertIn('attr = "blockchain_lite.__version__"', text)
        self.assertEqual(blockchain_lite.__version__, "1.0.0")


class TestMerkleOddNodeDuplication(unittest.TestCase):
    """D14: [cb,A,B] and [cb,A,B,B] share a Merkle root, but the duplicate block is rejected."""

    def test_duplicated_tail_tx_block_is_rejected(self) -> None:
        a = Wallet.generate("A", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=ENGINE)
        b = Wallet.generate("B", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=ENGINE)
        ledger = BlockchainLedger(difficulty=1, crypto_engine=ENGINE)
        ledger.create_genesis_block([(a.address, 10), (b.address, 10)], timestamp=T0)
        tx_a = a.create_signed_transfer(b.address, 3, ledger.get_spendable_utxos(a.address), timestamp=T0 + 1)
        tx_b = b.create_signed_transfer(a.address, 3, ledger.get_spendable_utxos(b.address), timestamp=T0 + 1)
        cb = Transaction.create_coinbase(a.address, 50, timestamp=1)

        honest = [cb, tx_a, tx_b]
        padded = honest + [tx_b]
        self.assertEqual(MerkleTree([t.tx_id for t in honest]).root, MerkleTree([t.tx_id for t in padded]).root)

        bad = ProofOfWorkMiner().mine_block(index=1, previous_hash=ledger.tip.block_hash,
                                            transactions=padded, difficulty=1, timestamp=T0 + 5)
        with self.assertRaises(ValidationError):
            ledger.append_mined_block(bad)
        self.assertEqual(ledger.height, 1)

        good = ProofOfWorkMiner().mine_block(index=1, previous_hash=ledger.tip.block_hash,
                                             transactions=honest, difficulty=1, timestamp=T0 + 5)
        self.assertEqual(good.merkle_root, bad.merkle_root)
        ledger.append_mined_block(good)
        self.assertEqual(ledger.height, 2)


if __name__ == "__main__":
    unittest.main()
