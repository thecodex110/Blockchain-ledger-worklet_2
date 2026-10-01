"""
Phase 3 Automated Verification Suite (Worklet 2: Blocks, Hashing, Merkle Trees & Chain):
- Worklet 2.1: Build a Block (`transactions`, `previous_hash`, `nonce`, `merkle_root`)
  and chain blocks by predecessor hash.
- Worklet 2.2: Build a binary Merkle tree over a block's transactions (for N = 1, 2, 3, 5, 8).
- Worklet 2.3: Produce and verify O(log2 N) Merkle inclusion proofs, and prove that
  1 altered byte or a swapped transaction breaks the Merkle root and proof (Pitfall 2).
- Worklet 2.4: Bit-level hash interface & avalanche behavior across block/tx structures.
- Worklet 2.5: Proof-of-Work mining with adjustable difficulty (leading zero bits).
"""

from __future__ import annotations

import unittest

from blockchain_lite.crypto.asymmetric import MIN_RSA_MODULUS_BITS, RSACryptoEngine
from blockchain_lite.crypto.hashing import default_hasher
from blockchain_lite.interfaces import (
    GENESIS_PREV_HASH,
    MerkleProof,
    TamperDetectedError,
)
from blockchain_lite.ledger.merkle import (
    MerkleTree,
    deserialize_merkle_proof,
    serialize_merkle_proof,
)
from blockchain_lite.ledger.pow import (
    ProofOfWorkMiner,
    count_leading_zero_bits,
    hash_meets_difficulty,
    verify_block_pow,
)
from blockchain_lite.models.block import BLOCK_HEADER_BYTE_SIZE, Block
from blockchain_lite.models.transaction import Transaction, TxOutput
from blockchain_lite.wallet.wallet import SpendableUTXO, Wallet


class TestWorklet2MerkleTreeAndProofs(unittest.TestCase):
    """Test Worklet 2.2 & 2.3: Binary Merkle Tree & Inclusion Proofs."""

    def _make_dummy_txs(self, count: int) -> list[Transaction]:
        addr = default_hasher.hash_bytes(b"recipient")
        return [
            Transaction.create_coinbase(
                recipient_address=addr,
                amount=100 + i,
                timestamp=1700000000 + i,
            )
            for i in range(count)
        ]

    def test_merkle_tree_and_inclusion_proofs_across_sizes(self) -> None:
        # Test N = 1, 2, 3, 4, 5, 7, 8 transactions
        for n in (1, 2, 3, 4, 5, 7, 8):
            txs = self._make_dummy_txs(n)
            tree = MerkleTree.from_transactions(txs)
            self.assertEqual(tree.leaf_count, n)
            expected_steps = MerkleTree.expected_proof_length(n)
            self.assertEqual(tree.height, expected_steps)

            for idx, tx in enumerate(txs):
                proof = tree.get_proof(tx.tx_id)
                self.assertEqual(proof.tx_index, idx)
                self.assertEqual(len(proof.steps), expected_steps)
                self.assertTrue(
                    MerkleTree.verify_proof(proof, expected_merkle_root=tree.root),
                    f"Valid Merkle proof failed for N={n}, idx={idx}",
                )

                # Verify canonical binary serialization of MerkleProof
                raw_proof = serialize_merkle_proof(proof)
                restored_proof = deserialize_merkle_proof(raw_proof)
                self.assertEqual(proof, restored_proof)
                self.assertTrue(
                    MerkleTree.verify_proof(restored_proof, expected_merkle_root=tree.root)
                )

    def test_merkle_tree_catches_one_altered_byte_and_swapped_transactions(self) -> None:
        """
        Pitfall 2 Check:
        "A Merkle tree that verifies the happy path but doesn't actually catch a
        swapped transaction — prove one altered byte breaks the root."
        """
        txs = self._make_dummy_txs(5)
        original_tree = MerkleTree.from_transactions(txs)
        proof_tx2 = original_tree.get_proof_by_index(2)
        self.assertTrue(MerkleTree.verify_proof(proof_tx2, original_tree.root))

        # Case 1: Change 1 byte in transaction #2 (amount 102 -> 103)
        mutated_txs = list(txs)
        mutated_txs[2] = Transaction.create_coinbase(
            recipient_address=txs[2].outputs[0].recipient_address,
            amount=103,
            timestamp=txs[2].timestamp,
        )
        mutated_tree = MerkleTree.from_transactions(mutated_txs)
        self.assertNotEqual(original_tree.root, mutated_tree.root)

        # Forged proof claiming mutated tx_id is in original_tree must fail
        forged_proof = MerkleProof(
            tx_id=mutated_txs[2].tx_id,
            tx_index=proof_tx2.tx_index,
            merkle_root=original_tree.root,
            steps=proof_tx2.steps,
        )
        self.assertFalse(MerkleTree.verify_proof(forged_proof, original_tree.root))

        # Case 2: Swap transaction #0 and transaction #1 without altering any bytes inside them
        swapped_txs = [txs[1], txs[0], txs[2], txs[3], txs[4]]
        swapped_tree = MerkleTree.from_transactions(swapped_txs)
        self.assertNotEqual(
            original_tree.root,
            swapped_tree.root,
            "Swapping two transactions MUST change the Merkle root!",
        )

        # Claiming tx #0 is at index 1 in the original tree must fail
        proof_tx0 = original_tree.get_proof_by_index(0)
        wrong_index_proof = MerkleProof(
            tx_id=proof_tx0.tx_id,
            tx_index=1,
            merkle_root=original_tree.root,
            steps=proof_tx0.steps,
        )
        self.assertFalse(MerkleTree.verify_proof(wrong_index_proof, original_tree.root))





    def test_merkle_tree_rejects_phantom_odd_tail_index_spoofing(self) -> None:
        """
        Verify F-003 fix: On a 3-transaction block (indices 0, 1, 2), leaf #2 is
        duplicated to pair with itself at level 0. A forged proof claiming tx #2
        is at phantom index 3 with a LEFT sibling equal to itself MUST be rejected.
        """
        txs = self._make_dummy_txs(3)
        tree = MerkleTree.from_transactions(txs)
        valid_proof_2 = tree.get_proof_by_index(2)
        self.assertTrue(MerkleTree.verify_proof(valid_proof_2, tree.root))

        from blockchain_lite.interfaces import MerkleProofStep
        from blockchain_lite.ledger.merkle import DIRECTION_LEFT

        spoofed_steps = (
            MerkleProofStep(
                sibling_hash=valid_proof_2.steps[0].sibling_hash,
                direction=DIRECTION_LEFT,
            ),
            *valid_proof_2.steps[1:],
        )
        spoofed_phantom_proof = MerkleProof(
            tx_id=txs[2].tx_id,
            tx_index=3,  # Phantom out-of-bounds index!
            merkle_root=tree.root,
            steps=spoofed_steps,
        )
        self.assertFalse(
            MerkleTree.verify_proof(spoofed_phantom_proof, tree.root),
            "MerkleTree.verify_proof must reject phantom odd-tail index spoofing!",
        )


class TestWorklet2BlocksChainingAndPoW(unittest.TestCase):
    """Test Worklet 2.1 & 2.5: Block model, Predecessor-Hash Chaining, and Adjustable PoW."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = RSACryptoEngine()
        cls.alice = Wallet.generate(label="Alice", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=cls.engine)
        cls.bob = Wallet.generate(label="Bob", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=cls.engine)
        cls.miner = ProofOfWorkMiner()

    def test_adjustable_difficulty_pow_mining_and_verification(self) -> None:
        coinbase_tx = Transaction.create_coinbase(
            recipient_address=self.alice.address,
            amount=500,
            timestamp=1700000000,
        )

        # Mine across adjustable difficulty levels: 0, 4, 8, and 10 leading zero bits
        for diff_bits in (0, 4, 8, 10):
            block, stats = self.miner.mine_block_with_stats(
                index=0,
                previous_hash=GENESIS_PREV_HASH,
                transactions=[coinbase_tx],
                difficulty=diff_bits,
                timestamp=1700000000,
            )
            self.assertEqual(len(block.header_bytes()), BLOCK_HEADER_BYTE_SIZE)
            self.assertEqual(stats.difficulty_bits, diff_bits)
            self.assertGreaterEqual(stats.hashes_tried, 1)
            self.assertTrue(hash_meets_difficulty(block.block_hash, diff_bits))
            self.assertGreaterEqual(count_leading_zero_bits(block.block_hash), diff_bits)

            # Verify PoW and crystallized integrity pass
            verify_block_pow(block)
            block.verify_crystallized_integrity()

            # Canonical serialization round-trip of Block
            raw_block = block.to_bytes()
            restored_block = Block.from_bytes(raw_block)
            self.assertEqual(block, restored_block)
            verify_block_pow(restored_block)
            restored_block.verify_crystallized_integrity()

    def test_hash_chaining_and_middle_block_tamper_evidence(self) -> None:
        """
        Worklet 2.1, Learning-Outcome Check 4 & Pitfall 3:
        Build a 3-block chain (Genesis -> Block 1 -> Block 2) linked by `previous_hash`.
        Prove that modifying 1 byte in Block 1 invalidates Block 1's Merkle root,
        Block 1's header hash, and breaks the `previous_hash` link in Block 2.
        """
        tx0 = Transaction.create_coinbase(self.alice.address, 1000, timestamp=1700000000)
        b0 = self.miner.mine_block(
            index=0,
            previous_hash=GENESIS_PREV_HASH,
            transactions=[tx0],
            difficulty=6,
            timestamp=1700000000,
        )

        tx1 = self.alice.create_signed_transfer(
            recipient_address=self.bob.address,
            amount=400,
            spendable_utxos=[
                SpendableUTXO(
                    tx_id=tx0.tx_id,
                    output_index=0,
                    amount=1000,
                    recipient_address=self.alice.address,
                )
            ],
            timestamp=1700000060,
        )
        b1 = self.miner.mine_block(
            index=1,
            previous_hash=b0.block_hash,
            transactions=[tx1],
            difficulty=6,
            timestamp=1700000060,
        )

        tx2 = self.bob.create_signed_transfer(
            recipient_address=self.alice.address,
            amount=150,
            spendable_utxos=[
                SpendableUTXO(
                    tx_id=tx1.tx_id,
                    output_index=0,
                    amount=400,
                    recipient_address=self.bob.address,
                )
            ],
            timestamp=1700000120,
        )
        b2 = self.miner.mine_block(
            index=2,
            previous_hash=b1.block_hash,
            transactions=[tx2],
            difficulty=6,
            timestamp=1700000120,
        )

        # Verify valid predecessor links across B0 -> B1 -> B2
        self.assertEqual(b0.previous_hash, GENESIS_PREV_HASH)
        self.assertEqual(b1.previous_hash, b0.block_hash)
        self.assertEqual(b2.previous_hash, b1.block_hash)

        # Now tamper with 1 byte inside Block 1's transaction (change Bob's amount 400 -> 401)
        tampered_tx1 = Transaction(
            tx_type=tx1.tx_type,
            timestamp=tx1.timestamp,
            inputs=tx1.inputs,
            outputs=(
                TxOutput(amount=401, recipient_address=self.bob.address),
                tx1.outputs[1],
            ),
        )
        tampered_b1 = Block(
            index=b1.index,
            previous_hash=b1.previous_hash,
            merkle_root=b1.merkle_root,
            timestamp=b1.timestamp,
            difficulty=b1.difficulty,
            nonce=b1.nonce,
            transactions=(tampered_tx1,),
            block_hash=b1.block_hash,
        )

        # 1. Tampered Block 1 fails crystallized Merkle root verification immediately
        with self.assertRaises(TamperDetectedError):
            tampered_b1.verify_crystallized_integrity()

        # 2. Even if the attacker recomputes Block 1's Merkle root, the old header hash & PoW break,
        #    AND Block 2's `previous_hash` no longer matches Block 1's new header hash!
        recomputed_merkle_b1 = tampered_b1.compute_merkle_root()
        forged_b1 = Block(
            index=b1.index,
            previous_hash=b1.previous_hash,
            merkle_root=recomputed_merkle_b1,
            timestamp=b1.timestamp,
            difficulty=b1.difficulty,
            nonce=b1.nonce,
            transactions=(tampered_tx1,),
            block_hash=b1.block_hash,
        )
        with self.assertRaises(TamperDetectedError):
            verify_block_pow(forged_b1)

        new_b1_header_hash = forged_b1.compute_header_hash()
        self.assertNotEqual(
            b2.previous_hash,
            new_b1_header_hash,
            "Modifying Block 1 MUST break the previous_hash link in Block 2!",
        )


if __name__ == "__main__":
    unittest.main()
