"""
Phase 13 (optional features): SPV header-chain verification and RSA key-size guidance.

SPV: with a trusted genesis hash, the light client takes the Merkle root from a header
chain it verified itself (links, PoW, scheduled difficulty, timestamps) instead of
trusting the root reported by the same server.
"""

from __future__ import annotations

import unittest
from typing import Any, Dict

from blockchain_lite.crypto.asymmetric import RECOMMENDED_PRODUCTION_RSA_BITS, weak_key_warning
from blockchain_lite.interfaces import TamperDetectedError
from blockchain_lite.ledger.chain import BlockchainLedger
from blockchain_lite.ledger.merkle import serialize_merkle_proof
from blockchain_lite.ledger.pow import ProofOfWorkMiner
from blockchain_lite.models.block import Block, BlockHeader
from blockchain_lite.models.transaction import Transaction
from blockchain_lite.network.client import WalletClient
from blockchain_lite.network.server import InMemoryTransport, LedgerServerDispatcher
from blockchain_lite.network.transport import ClientTransport, NetworkRPCError
from blockchain_lite.wallet.wallet import Wallet

T0 = 1700000000
DIFF = 4


class ForgingTransport(ClientTransport):
    """A malicious server: serves honest data except a forged block at `forged.index`."""

    def __init__(self, inner: ClientTransport, forged: Block) -> None:
        self.inner, self.forged = inner, forged

    def send_request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if method == "get_headers":
            headers = list(self.inner.send_request(method, params)["headers_hex"])
            headers[self.forged.index] = self.forged.header_bytes().hex()
            return {"headers_hex": headers}
        if method == "get_block" and params["block_index"] == self.forged.index:
            return {"merkle_root_hex": self.forged.merkle_root_hex}
        if method == "get_merkle_proof":
            proof = self.forged.generate_merkle_proof(bytes.fromhex(params["tx_id_hex"]))
            return {"proof_bytes_hex": serialize_merkle_proof(proof).hex()}
        return self.inner.send_request(method, params)


class TestSPVHeaderChain(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.alice = Wallet.generate("A", bit_length=384)
        cls.bob = Wallet.generate("B", bit_length=384)
        cls.mallory = Wallet.generate("M", bit_length=384)
        ledger = BlockchainLedger(difficulty=DIFF)
        ledger.create_genesis_block([(cls.alice.address, 100)], timestamp=T0)
        utxos = ledger.get_spendable_utxos(cls.alice.address)
        cls.real_tx = cls.alice.create_signed_transfer(cls.bob.address, 10, utxos, timestamp=T0 + 1)
        # Signed but never mined: what a lying server wants Mallory's victim to accept.
        cls.fake_tx = cls.alice.create_signed_transfer(cls.mallory.address, 90, utxos, timestamp=T0 + 2)
        ledger.submit_transaction(cls.real_tx)
        ledger.mine_pending_transactions(miner_address=cls.bob.address, timestamp=T0 + 10)
        ledger.mine_pending_transactions(miner_address=cls.bob.address, timestamp=T0 + 20)
        cls.ledger = ledger
        cls.genesis = ledger.genesis_hash
        cls.honest = InMemoryTransport(LedgerServerDispatcher(ledger))

    def _client(self, transport: ClientTransport) -> WalletClient:
        return WalletClient(self.mallory, transport)

    def _forge_block1(self, difficulty: int) -> Block:
        return ProofOfWorkMiner().mine_block(
            index=1, previous_hash=self.genesis,
            transactions=[Transaction.create_coinbase(self.mallory.address, 50, timestamp=1), self.fake_tx],
            difficulty=difficulty, timestamp=T0 + 10)

    def test_honest_inclusion_verifies_from_trusted_genesis(self) -> None:
        client = self._client(self.honest)
        self.assertTrue(client.verify_transaction_inclusion_spv(
            1, self.real_tx.tx_id, trusted_genesis_hash=self.genesis, params=self.ledger.params))
        headers = client.fetch_verified_headers(2, self.genesis, self.ledger.params)
        self.assertEqual([h.index for h in headers], [0, 1, 2])
        self.assertEqual(headers[2].compute_hash(), self.ledger.tip.block_hash)

    def test_forged_low_difficulty_block_fools_legacy_spv_but_not_header_check(self) -> None:
        client = self._client(ForgingTransport(self.honest, self._forge_block1(difficulty=0)))
        # Legacy mode trusts the server's root: the attack succeeds (the documented weakness).
        self.assertTrue(client.verify_transaction_inclusion_spv(1, self.fake_tx.tx_id))
        # Header-chain mode: the forged header breaks the difficulty schedule (and the link
        # from header 2), so the proof is rejected.
        self.assertFalse(client.verify_transaction_inclusion_spv(
            1, self.fake_tx.tx_id, trusted_genesis_hash=self.genesis, params=self.ledger.params))

    def test_alien_chain_rejected_by_genesis_anchor(self) -> None:
        alien = BlockchainLedger(difficulty=DIFF)
        alien.create_genesis_block([(self.alice.address, 100)], timestamp=T0 + 999)
        utxos = alien.get_spendable_utxos(self.alice.address)
        tx = self.alice.create_signed_transfer(self.mallory.address, 90, utxos, timestamp=T0 + 1000)
        alien.submit_transaction(tx)
        alien.mine_pending_transactions(miner_address=self.mallory.address, timestamp=T0 + 1010)
        client = self._client(InMemoryTransport(LedgerServerDispatcher(alien)))
        self.assertTrue(client.verify_transaction_inclusion_spv(1, tx.tx_id))  # legacy: fooled
        self.assertFalse(client.verify_transaction_inclusion_spv(
            1, tx.tx_id, trusted_genesis_hash=self.genesis, params=self.ledger.params))

    def test_limitation_validly_mined_fork_at_tip_is_not_detectable(self) -> None:
        """Known SPV limit (documented): a correctly mined fork at the requested height
        is a valid chain from genesis; only confirmation depth / heaviest-chain knowledge
        can reject it. Here the client asks only up to height 1, so it is accepted."""
        forged = self._forge_block1(difficulty=DIFF)
        client = self._client(ForgingTransport(self.honest, forged))
        self.assertTrue(client.verify_transaction_inclusion_spv(
            1, self.fake_tx.tx_id, trusted_genesis_hash=self.genesis, params=self.ledger.params))
        # ...but one confirmation deeper the forged header no longer links to header 2.
        with self.assertRaises(TamperDetectedError):
            client.fetch_verified_headers(2, self.genesis, self.ledger.params)

    def test_get_headers_rpc_bounds(self) -> None:
        self.assertEqual(len(self.honest.send_request("get_headers", {"start_index": 1, "count": 50})["headers_hex"]), 2)
        self.assertEqual(self.honest.send_request("get_headers", {"start_index": 99, "count": 1})["headers_hex"], [])
        for bad in ({"start_index": 0, "count": 0}, {"start_index": 0, "count": 5000}, {"start_index": -1, "count": 1}):
            with self.assertRaises(NetworkRPCError):
                self.honest.send_request("get_headers", bad)
        raw = bytes.fromhex(self.honest.send_request("get_headers", {"start_index": 1, "count": 1})["headers_hex"][0])
        self.assertEqual(BlockHeader.from_bytes(raw).to_bytes(), raw)


class TestRSAKeySizeGuidance(unittest.TestCase):
    def test_weak_key_warning_threshold(self) -> None:
        for bits in (384, 512, 1024, 2047):
            banner = weak_key_warning(bits)
            self.assertIsNotNone(banner)
            assert banner is not None
            self.assertIn(str(RECOMMENDED_PRODUCTION_RSA_BITS), banner)
        self.assertIsNone(weak_key_warning(2048))
        self.assertIsNone(weak_key_warning(4096))

    def test_2048_bit_wallet_end_to_end(self) -> None:
        strong = Wallet.generate("Strong", bit_length=2048)  # ~1 s with pure-Python Miller-Rabin
        self.assertEqual(strong.public_key.bit_length, 2048)
        self.assertTrue(strong.public_key.is_production_grade)
        recipient = Wallet.generate("R", bit_length=384)
        ledger = BlockchainLedger(difficulty=1)
        ledger.create_genesis_block([(strong.address, 100)], timestamp=T0)
        tx = strong.create_signed_transfer(
            recipient.address, 40, ledger.get_spendable_utxos(strong.address), fee=1, timestamp=T0 + 1)
        self.assertTrue(tx.verify_signatures())
        ledger.submit_transaction(tx)
        ledger.mine_pending_transactions(miner_address=recipient.address, timestamp=T0 + 5)
        self.assertEqual(ledger.get_balance(recipient.address), 40 + 50 + 1)
        self.assertTrue(ledger.validate_full_chain(force=True).is_valid)

    def test_dashboard_demo_accepts_rsa_bits(self) -> None:
        from blockchain_lite.network.web_dashboard import create_demo_ledger_and_wallets
        _, wallets = create_demo_ledger_and_wallets(rsa_bits=512)
        self.assertTrue(all(w.public_key.bit_length == 512 for w in wallets.values()))


if __name__ == "__main__":
    unittest.main()
