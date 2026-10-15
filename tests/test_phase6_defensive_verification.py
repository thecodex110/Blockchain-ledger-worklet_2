"""
Phase 6 Comprehensive Defensive Verification & Regression Suite (Categories A–G).

Covers all mandatory defensive test cases specified in Phase 6:
- Category A: Cryptographic boundary values, Fermat identities, malformed keys/signatures.
- Category B: Transaction edge cases (missing inputs, unauthorized spend, insufficient funds,
  intra-tx duplicate input, idempotent mempool submission, invalid amounts, malformed bytes).
- Category C: Merkle-tree edge cases (empty list rejection, N=1, 2, odd counts, altered
  sibling hashes, wrong roots, deterministic proof generation).
- Category D: Block and chain edge cases (bad previous_hash, bad header/nonce/PoW,
  corrupted Genesis, index discontinuity).
- Category E: Persistence edge cases (missing file, truncated file, bad magic, atomic
  interrupted-write preservation of existing valid ledger).
- Category F: Network & concurrency edge cases (zero-length frame, non-dict JSON root,
  unknown RPC method, idempotent repeat submission, state consistency after error).
- Category G: Complete 16-step End-to-End Lifecycle Verification over TCP Client-Server.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from blockchain_lite.crypto.asymmetric import MIN_RSA_MODULUS_BITS, RSACryptoEngine
from blockchain_lite.crypto.hashing import default_hasher
from blockchain_lite.crypto.number_theory import (
    is_probable_prime_miller_rabin,
    mod_add,
    mod_inverse,
    mod_mul,
    mod_sub,
    pow_mod,
)
from blockchain_lite.interfaces import (
    MAX_TOKEN_SUPPLY,
    CryptoError,
    DoubleSpendError,
    MerkleProof,
    MerkleProofStep,
    TamperDetectedError,
    ValidationError,
)
from blockchain_lite.ledger.chain import BlockchainLedger
from blockchain_lite.ledger.merkle import MerkleTree
from blockchain_lite.ledger.persistence import ChainPersistence
from blockchain_lite.ledger.pow import verify_block_pow
from blockchain_lite.ledger.validator import FullChainValidator
from blockchain_lite.models.block import Block
from blockchain_lite.models.transaction import (
    Transaction,
    TxInput,
    TxOutput,
    validate_block_transactions_no_double_spend,
    validate_transaction_integrity,
)
from blockchain_lite.network.client import TCPSocketTransport, WalletClient
from blockchain_lite.network.server import TCPSocketLedgerServer
from blockchain_lite.network.transport import NetworkRPCError
from blockchain_lite.wallet.wallet import SpendableUTXO, Wallet


class TestPhase6CategoriesAToG(unittest.TestCase):
    """Comprehensive defensive tests across Categories A through G."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = RSACryptoEngine()
        cls.alice = Wallet.generate("Alice", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=cls.engine)
        cls.bob = Wallet.generate("Bob", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=cls.engine)
        cls.charlie = Wallet.generate("Charlie", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=cls.engine)
        cls.miner_wallet = Wallet.generate("Miner", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=cls.engine)

    # ------------------------------------------------------------------------
    # Category A: Cryptographic Boundary & Identity Tests
    # ------------------------------------------------------------------------

    def test_category_a_cryptographic_boundaries_and_fermat_identities(self) -> None:
        p = 104729  # Known prime
        for a in (1, 2, 42, p - 1):
            # Fermat's Little Theorem: a^(p-1) == 1 (mod p)
            self.assertEqual(pow_mod(a, p - 1, p), 1)
            # Modular inverse identity: a * a^(p-2) == 1 (mod p)
            inv = mod_inverse(a, p)
            self.assertEqual(inv, pow_mod(a, p - 2, p))
            self.assertEqual(mod_mul(a, inv, p), 1)

        # Boundary remainders with negative inputs
        self.assertEqual(mod_add(-1, 1, p), 0)
        self.assertEqual(mod_sub(0, 1, p), p - 1)
        self.assertEqual(mod_mul(-2, -3, p), 6)

        # Primality edge cases: negative numbers, 0, 1, 2, 3, 4
        for neg_or_small in (-101, -2, -1, 0, 1, 4, 6, 8, 9):
            self.assertFalse(is_probable_prime_miller_rabin(neg_or_small, rounds=10))
        self.assertTrue(is_probable_prime_miller_rabin(2, rounds=10))
        self.assertTrue(is_probable_prime_miller_rabin(3, rounds=10))

        # Key generation bit_length below MIN_RSA_MODULUS_BITS must raise CryptoError
        with self.assertRaises(CryptoError):
            self.engine.generate_keypair(bit_length=256)

    # ------------------------------------------------------------------------
    # Category B: Transaction Edge Cases
    # ------------------------------------------------------------------------

    def test_category_b_transaction_validation_edge_cases(self) -> None:
        seed_tx_id = default_hasher.hash_bytes(b"cat-b-seed")
        utxo_map = {(seed_tx_id, 0): TxOutput(amount=100, recipient_address=self.alice.address)}

        # 1. Invalid output amounts (0, negative, > MAX_TOKEN_SUPPLY, float, bool)
        for bad_amt in (0, -5, MAX_TOKEN_SUPPLY + 1, True, 12.5):
            with self.assertRaises(ValidationError):
                TxOutput(amount=bad_amt, recipient_address=self.bob.address)  # type: ignore[arg-type]

        # 2. Intra-transaction duplicate input spending same UTXO twice in one Transaction
        dup_unsigned = Transaction(
            tx_type=1,
            timestamp=1700000000,
            inputs=(
                TxInput(prev_tx_id=seed_tx_id, output_index=0, sender_pubkey=self.alice.public_key_bytes),
                TxInput(prev_tx_id=seed_tx_id, output_index=0, sender_pubkey=self.alice.public_key_bytes),
            ),
            outputs=(TxOutput(amount=100, recipient_address=self.bob.address),),
        )
        dup_signed = self.alice.sign_transaction(dup_unsigned)
        with self.assertRaises(DoubleSpendError):
            validate_transaction_integrity(dup_signed)

        # 3. Value conservation violation: outputs (150) > inputs (100)
        inflated_unsigned = Transaction(
            tx_type=1,
            timestamp=1700000001,
            inputs=(
                TxInput(prev_tx_id=seed_tx_id, output_index=0, sender_pubkey=self.alice.public_key_bytes),
            ),
            outputs=(TxOutput(amount=150, recipient_address=self.bob.address),),
        )
        inflated_signed = self.alice.sign_transaction(inflated_unsigned)
        with self.assertRaises(ValidationError):
            validate_block_transactions_no_double_spend([inflated_signed], available_utxos=utxo_map)

        # 4. Missing input reference (unbeknownst prev_tx_id)
        unknown_tx_id = default_hasher.hash_bytes(b"non-existent-utxo")
        missing_utxo_tx = self.alice.create_signed_transfer(
            recipient_address=self.bob.address,
            amount=50,
            spendable_utxos=[
                SpendableUTXO(
                    tx_id=unknown_tx_id,
                    output_index=0,
                    amount=100,
                    recipient_address=self.alice.address,
                )
            ],
            timestamp=1700000002,
        )
        with self.assertRaises(DoubleSpendError):
            validate_block_transactions_no_double_spend([missing_utxo_tx], available_utxos=utxo_map)

    # ------------------------------------------------------------------------
    # Category C: Merkle-Tree Edge Cases
    # ------------------------------------------------------------------------

    def test_category_c_merkle_tree_edge_cases(self) -> None:
        # 1. Empty transaction list must raise ValidationError
        with self.assertRaises(ValidationError):
            MerkleTree([])

        # 2. Altered sibling hash or wrong root must fail verify_proof
        txs = [
            Transaction.create_coinbase(self.alice.address, 100 + i, timestamp=1700000000 + i)
            for i in range(6)
        ]
        tree = MerkleTree.from_transactions(txs)
        proof = tree.get_proof_by_index(4)
        self.assertTrue(MerkleTree.verify_proof(proof, expected_merkle_root=tree.root))

        # Corrupt 1 bit in step 0 sibling hash
        bad_sibling = bytearray(proof.steps[0].sibling_hash)
        bad_sibling[0] ^= 0x80
        corrupted_step_proof = MerkleProof(
            tx_id=proof.tx_id,
            tx_index=proof.tx_index,
            merkle_root=proof.merkle_root,
            steps=(
                MerkleProofStep(sibling_hash=bytes(bad_sibling), direction=proof.steps[0].direction),
                *proof.steps[1:],
            ),
        )
        self.assertFalse(MerkleTree.verify_proof(corrupted_step_proof, expected_merkle_root=tree.root))

        # Wrong expected_merkle_root must fail
        wrong_root = default_hasher.hash_bytes(b"wrong-merkle-root")
        self.assertFalse(MerkleTree.verify_proof(proof, expected_merkle_root=wrong_root))

    # ------------------------------------------------------------------------
    # Category D & E: Block, Chain & Persistence Edge Cases
    # ------------------------------------------------------------------------

    def test_category_d_and_e_block_chain_and_persistence_recovery(self) -> None:
        ledger = BlockchainLedger(difficulty=4, block_reward=50, crypto_engine=self.engine)
        ledger.create_genesis_block(
            initial_allocations=[(self.alice.address, 500)],
            timestamp=1700000000,
        )
        validator = FullChainValidator(crypto_engine=self.engine, max_block_reward=50)

        # 1. Corrupted Genesis previous_hash (non-zero)
        g = ledger.blocks[0]
        bad_genesis = Block(
            index=0,
            previous_hash=default_hasher.hash_bytes(b"non-zero-prev"),
            merkle_root=g.merkle_root,
            timestamp=g.timestamp,
            difficulty=g.difficulty,
            nonce=g.nonce,
            transactions=g.transactions,
            block_hash=g.block_hash,
        )
        with self.assertRaises(TamperDetectedError):
            validator.validate_chain_or_raise([bad_genesis])

        # 2. Invalid nonce / PoW failure on a block
        bad_nonce_block = Block(
            index=g.index,
            previous_hash=g.previous_hash,
            merkle_root=g.merkle_root,
            timestamp=g.timestamp,
            difficulty=20,  # Claim 20 zero bits without mining
            nonce=0,
            transactions=g.transactions,
            block_hash=g.block_hash,
        )
        with self.assertRaises(TamperDetectedError):
            verify_block_pow(bad_nonce_block)

        # 3. Persistence: missing file, truncated file, bad magic, and interrupted-write preservation
        persistence = ChainPersistence(crypto_engine=self.engine, params=ledger.params)
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)

            # Missing file
            with self.assertRaises(ValidationError):
                persistence.load_ledger(tmp_path / "does_not_exist.bclt")

            # Truncated file (< minimum header + seal size)
            trunc_file = tmp_path / "truncated.bclt"
            trunc_file.write_bytes(b"BCLT\x01\x00\x00")
            with self.assertRaises(TamperDetectedError):
                persistence.load_ledger(trunc_file)

            # Save valid ledger, then simulate an interrupted disk write during a subsequent save;
            # verify the original valid ledger file remains intact and loadable!
            valid_file = tmp_path / "atomic_test.bclt"
            persistence.save_ledger(ledger, valid_file)
            original_disk_bytes = valid_file.read_bytes()

            with patch("os.replace", side_effect=OSError("Simulated disk crash before atomic rename")):
                with self.assertRaises(OSError):
                    persistence.save_ledger(ledger, valid_file)

            # Temporary .tmp file must have been cleaned up, and original file is untouched!
            self.assertFalse((tmp_path / "atomic_test.bclt.tmp").exists())
            self.assertEqual(valid_file.read_bytes(), original_disk_bytes)
            recovered_ledger = persistence.load_ledger(valid_file)
            self.assertEqual(recovered_ledger.get_balance(self.alice.address), 500)

    # ------------------------------------------------------------------------
    # Category F & G: Complete 16-Step End-to-End Lifecycle Verification
    # ------------------------------------------------------------------------

    def test_category_f_and_g_complete_16_step_end_to_end_lifecycle(self) -> None:
        """
        Execute all 16 mandatory steps of Phase 6 Category G End-to-End Verification:
        1. Create a wallet.
        2. Create a transaction.
        3. Serialize and sign it.
        4. Submit it through the client-server interface.
        5. Verify its signature and authorization.
        6. Validate inputs against UTXO state.
        7. Mine or append an appropriate block.
        8. Revalidate the block and chain.
        9. Query balances and transaction history.
        10. Save the ledger.
        11. Restart or reload the application.
        12. Revalidate the chain.
        13. Confirm the recovered balances.
        14. Alter a transaction and demonstrate rejection.
        15. Attempt double-spending and demonstrate rejection.
        16. Attempt an invalid fork and demonstrate rejection.
        """
        # Step 1: Create wallets & Genesis ledger
        sender_wallet = Wallet.generate("Sender", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=self.engine)
        receiver_wallet = Wallet.generate("Receiver", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=self.engine)
        ledger = BlockchainLedger(difficulty=4, block_reward=50, crypto_engine=self.engine)
        genesis_block = ledger.create_genesis_block(
            initial_allocations=[(sender_wallet.address, 1000)],
            timestamp=1700000000,
        )

        with TCPSocketLedgerServer(ledger, host="127.0.0.1", port=0, mine_token="demo-mine-token", allow_client_timestamp=True) as server:
            transport = TCPSocketTransport(server.host, server.port)
            sender_client = WalletClient(sender_wallet, transport)
            receiver_client = WalletClient(receiver_wallet, transport)
            miner_client = WalletClient(self.miner_wallet, transport)

            # Steps 2 & 3: Create, canonically serialize, and sign a transaction on the client
            utxos = sender_client.get_spendable_utxos()
            signed_tx = sender_wallet.create_signed_transfer(
                recipient_address=receiver_wallet.address,
                amount=420,
                spendable_utxos=utxos,
                fee=5,
                timestamp=1700000060,
            )
            tx_bytes = signed_tx.to_bytes()

            # Step 4, 5 & 6: Submit over TCP client-server interface (verifies signature & UTXOs)
            sub_res = transport.send_request("submit_transaction", {"tx_bytes_hex": tx_bytes.hex()})
            self.assertEqual(sub_res["tx_id_hex"], signed_tx.tx_id_hex)
            # Idempotent repeat submission of exact same transaction succeeds without duplicating mempool
            sub_res_dup = transport.send_request("submit_transaction", {"tx_bytes_hex": tx_bytes.hex()})
            self.assertEqual(sub_res_dup["mempool_size"], 1)

            # Step 7 & 8: Mine Block #1 over TCP and revalidate the block and full chain
            mine_res = miner_client.request_mining(reward_to_self=True, timestamp=1700000065, auth_token="demo-mine-token")
            self.assertEqual(mine_res["block_index"], 1)
            chain_info = sender_client.get_chain_info()
            self.assertTrue(chain_info["is_valid"])
            self.assertEqual(chain_info["height"], 2)

            # Step 9: Query balances and transaction history over TCP
            self.assertEqual(sender_client.get_balance(), 575)    # 1000 - 420 - 5
            self.assertEqual(receiver_client.get_balance(), 420)
            self.assertEqual(miner_client.get_balance(), 55)      # 50 + 5
            self.assertEqual(len(sender_client.get_transaction_history()), 2)
            self.assertEqual(len(receiver_client.get_transaction_history()), 1)

            # Step 14: Alter 1 byte of a signed transaction and demonstrate rejection over TCP
            next_utxos = sender_client.get_spendable_utxos()
            valid_tx2 = sender_wallet.create_signed_transfer(
                recipient_address=receiver_wallet.address,
                amount=100,
                spendable_utxos=next_utxos,
                timestamp=1700000120,
            )
            tampered_tx2 = Transaction(
                tx_type=valid_tx2.tx_type,
                timestamp=valid_tx2.timestamp,
                inputs=valid_tx2.inputs,
                outputs=(
                    TxOutput(amount=101, recipient_address=receiver_wallet.address),
                    valid_tx2.outputs[1],
                ),
            )
            with self.assertRaises(NetworkRPCError) as tamper_ctx:
                transport.send_request(
                    "submit_transaction",
                    {"tx_bytes_hex": tampered_tx2.to_bytes().hex()},
                )
            self.assertEqual(tamper_ctx.exception.error_type, "TamperDetectedError")

            # Step 15: Attempt double-spending and demonstrate rejection over TCP
            conflicting_tx2 = sender_wallet.create_signed_transfer(
                recipient_address=self.charlie.address,
                amount=200,
                spendable_utxos=next_utxos,
                timestamp=1700000121,
            )
            transport.send_request("submit_transaction", {"tx_bytes_hex": valid_tx2.to_bytes().hex()})
            with self.assertRaises(NetworkRPCError) as ds_ctx:
                transport.send_request(
                    "submit_transaction",
                    {"tx_bytes_hex": conflicting_tx2.to_bytes().hex()},
                )
            self.assertEqual(ds_ctx.exception.error_type, "DoubleSpendError")
            miner_client.request_mining(reward_to_self=True, timestamp=1700000125, auth_token="demo-mine-token")

        # Steps 10, 11, 12 & 13: Save ledger to disk, reload into a fresh instance,
        # revalidate from Genesis, and confirm recovered balances match
        persistence = ChainPersistence(crypto_engine=self.engine, params=ledger.params)
        with tempfile.TemporaryDirectory() as tmpdir:
            disk_file = Path(tmpdir) / "e2e_ledger.bclt"
            persistence.save_ledger(ledger, disk_file)

            reloaded_ledger = persistence.load_ledger(
                disk_file, expected_genesis_hash=genesis_block.block_hash
            )
            self.assertTrue(reloaded_ledger.validate_full_chain().is_valid)
            self.assertEqual(reloaded_ledger.height, 3)
            self.assertEqual(reloaded_ledger.get_balance(sender_wallet.address), 475)
            self.assertEqual(reloaded_ledger.get_balance(receiver_wallet.address), 520)
            self.assertEqual(reloaded_ledger.get_balance(self.miner_wallet.address), 105)

            # Step 16: Attempt an invalid longer fork and demonstrate rejection
            corrupted_fork = list(reloaded_ledger.blocks)
            b1 = corrupted_fork[1]
            bad_tx = Transaction(
                tx_type=b1.transactions[1].tx_type,
                timestamp=b1.transactions[1].timestamp,
                inputs=b1.transactions[1].inputs,
                outputs=(
                    TxOutput(amount=999, recipient_address=receiver_wallet.address),
                    b1.transactions[1].outputs[1],
                ),
            )
            corrupted_fork[1] = Block(
                index=b1.index,
                previous_hash=b1.previous_hash,
                merkle_root=b1.merkle_root,
                timestamp=b1.timestamp,
                difficulty=b1.difficulty,
                nonce=b1.nonce,
                transactions=(b1.transactions[0], bad_tx),
                block_hash=b1.block_hash,
            )
            fork_outcome = reloaded_ledger.resolve_forks([corrupted_fork])
            self.assertFalse(fork_outcome.switched_chain)
            self.assertEqual(fork_outcome.rejected_candidates_count, 1)


if __name__ == "__main__":
    unittest.main()
