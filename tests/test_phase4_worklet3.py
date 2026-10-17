"""
Phase 4 Automated Verification Suite (Worklet 3: Validation, Wallet & Persistence):
- Worklet 3.1: Validate a full chain (hashes, signatures, Merkle roots) from Genesis.
- Worklet 3.2: Resolve forks with a longest-valid-chain rule; show one altered
  transaction invalidates the rest.
- Worklet 3.3: Compute balances by scanning unspent outputs; build a ledger query interface.
- Worklet 3.4: Persist the chain and reload it, re-validating; add integrity checks
  for on-disk tampering (Pitfall 5).
- Worklet 3.5: Measure how difficulty affects mining time.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from blockchain_lite.benchmarks.pow_benchmark import (
    format_benchmark_markdown_table,
    run_difficulty_benchmark,
)
from blockchain_lite.crypto.asymmetric import MIN_RSA_MODULUS_BITS, RSACryptoEngine
from blockchain_lite.interfaces import (
    TamperDetectedError,
)
from blockchain_lite.ledger.chain import BlockchainLedger
from blockchain_lite.ledger.merkle import MerkleTree
from blockchain_lite.ledger.persistence import ChainPersistence
from blockchain_lite.ledger.pow import ProofOfWorkMiner
from blockchain_lite.ledger.validator import FullChainValidator
from blockchain_lite.models.block import Block
from blockchain_lite.models.transaction import Transaction, TxOutput
from blockchain_lite.wallet.wallet import Wallet


class TestWorklet3ValidationForksQueriesAndPersistence(unittest.TestCase):
    """Comprehensive tests for Worklet 3 tasks 3.1 through 3.5."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = RSACryptoEngine()
        cls.alice = Wallet.generate("Alice", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=cls.engine)
        cls.bob = Wallet.generate("Bob", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=cls.engine)
        cls.charlie = Wallet.generate("Charlie", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=cls.engine)
        cls.miner_wallet = Wallet.generate("Miner", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=cls.engine)

    def _build_sample_ledger(self, difficulty: int = 6) -> BlockchainLedger:
        ledger = BlockchainLedger(
            difficulty=difficulty,
            block_reward=50,
            crypto_engine=self.engine,
        )
        # Genesis allocates 1000 to Alice and 500 to Bob
        ledger.create_genesis_block(
            initial_allocations=[
                (self.alice.address, 1000),
                (self.bob.address, 500),
            ],
            timestamp=1700000000,
        )

        # Block 1: Alice sends 300 to Bob (with fee 5)
        tx1 = self.alice.create_signed_transfer(
            recipient_address=self.bob.address,
            amount=300,
            spendable_utxos=ledger.get_spendable_utxos(self.alice.address),
            fee=5,
            timestamp=1700000060,
        )
        ledger.submit_transaction(tx1.to_bytes())
        ledger.mine_pending_transactions(
            miner_address=self.miner_wallet.address,
            timestamp=1700000065,
        )

        # Block 2: Bob sends 200 to Charlie (with fee 2)
        tx2 = self.bob.create_signed_transfer(
            recipient_address=self.charlie.address,
            amount=200,
            spendable_utxos=ledger.get_spendable_utxos(self.bob.address),
            fee=2,
            timestamp=1700000120,
        )
        ledger.submit_transaction(tx2.to_bytes())
        ledger.mine_pending_transactions(
            miner_address=self.miner_wallet.address,
            timestamp=1700000125,
        )
        return ledger

    def test_worklet3_1_and_3_3_full_chain_validation_and_utxo_queries(self) -> None:
        ledger = self._build_sample_ledger(difficulty=6)
        self.assertEqual(ledger.height, 3)

        # Verify full chain from Genesis
        report = ledger.validate_full_chain()
        self.assertTrue(report.is_valid)
        self.assertEqual(report.block_count, 3)

        # Check UTXO balances:
        # Alice: started with 1000, sent 300 + fee 5 -> 695
        # Bob: started with 500, received 300 (total 800), sent 200 + fee 2 -> 598
        # Charlie: received 200 -> 200
        # Miner: Block 1 (50 + 5 = 55) + Block 2 (50 + 2 = 52) -> 107
        self.assertEqual(ledger.get_balance(self.alice.address), 695)
        self.assertEqual(ledger.get_balance(self.bob.address), 598)
        self.assertEqual(ledger.get_balance(self.charlie.address), 200)
        self.assertEqual(ledger.get_balance(self.miner_wallet.address), 107)

        # Verify total supply conservation: 1500 genesis + 50*2 block rewards = 1600
        self.assertEqual(ledger.utxo_set.total_supply, 1600)

        # Verify Merkle inclusion proof retrieval via LedgerQueryInterface
        block1_transfer_tx = ledger.blocks[1].transactions[1]
        proof = ledger.get_merkle_proof(1, block1_transfer_tx.tx_id)
        self.assertIsNotNone(proof)
        assert proof is not None
        self.assertTrue(
            MerkleTree.verify_proof(proof, expected_merkle_root=ledger.blocks[1].merkle_root)
        )

        # Verify transaction history query
        bob_history = ledger.get_transaction_history(self.bob.address)
        self.assertEqual(len(bob_history), 3)  # Genesis allocation, received in Block 1, sent in Block 2

    def test_worklet3_2_longest_valid_chain_fork_resolution_and_poisoned_fork(self) -> None:
        """
        Worklet 3.2:
        - Resolve forks with a longest-valid-chain rule.
        - Show that one altered transaction in a longer competing branch invalidates
          the rest and causes the poisoned fork to be rejected.
        """
        main_ledger = self._build_sample_ledger(difficulty=6)
        self.assertEqual(main_ledger.height, 3)

        # Construct a competing Fork B that shares Genesis (Block 0) and Block 1,
        # but diverges at Block 2 and mines up to Block 3 (total length = 4 blocks).
        fork_b = BlockchainLedger(difficulty=6, block_reward=50, crypto_engine=self.engine)
        fork_b.load_verified_chain(main_ledger.blocks[:2])

        # In Fork B Block 2, Alice sends 100 to Charlie
        fork_tx2 = self.alice.create_signed_transfer(
            recipient_address=self.charlie.address,
            amount=100,
            spendable_utxos=fork_b.get_spendable_utxos(self.alice.address),
            fee=0,
            timestamp=1700000200,
        )
        fork_b.submit_transaction(fork_tx2.to_bytes())
        fork_b.mine_pending_transactions(
            miner_address=self.miner_wallet.address,
            timestamp=1700000205,
        )

        # In Fork B Block 3, Charlie sends 40 back to Alice
        fork_tx3 = self.charlie.create_signed_transfer(
            recipient_address=self.alice.address,
            amount=40,
            spendable_utxos=fork_b.get_spendable_utxos(self.charlie.address),
            fee=0,
            timestamp=1700000260,
        )
        fork_b.submit_transaction(fork_tx3.to_bytes())
        fork_b.mine_pending_transactions(
            miner_address=self.miner_wallet.address,
            timestamp=1700000265,
        )
        self.assertEqual(fork_b.height, 4)

        # Now create a Poisoned Fork C of length 4 where 1 byte in Block 1's transfer
        # transaction is altered (changing Bob's received amount from 300 to 301).
        poisoned_blocks = list(fork_b.blocks)
        orig_b1 = poisoned_blocks[1]
        orig_transfer = orig_b1.transactions[1]
        mutated_transfer = Transaction(
            tx_type=orig_transfer.tx_type,
            timestamp=orig_transfer.timestamp,
            inputs=orig_transfer.inputs,
            outputs=(
                TxOutput(amount=301, recipient_address=self.bob.address),
                orig_transfer.outputs[1],
            ),
        )
        poisoned_blocks[1] = Block(
            index=orig_b1.index,
            previous_hash=orig_b1.previous_hash,
            merkle_root=orig_b1.merkle_root,
            timestamp=orig_b1.timestamp,
            difficulty=orig_b1.difficulty,
            nonce=orig_b1.nonce,
            transactions=(orig_b1.transactions[0], mutated_transfer),
            block_hash=orig_b1.block_hash,
        )

        # Verify TamperCascadeReport traces every broken link from Block 1 to Block 3
        validator = FullChainValidator(crypto_engine=self.engine, max_block_reward=50)
        cascade = validator.trace_tamper_cascade(
            original_chain=fork_b.blocks,
            tampered_chain=poisoned_blocks,
            block_index=1,
            tx_index=1,
        )
        self.assertFalse(cascade.signature_valid_after_tamper)
        self.assertFalse(cascade.merkle_root_matches_header)
        self.assertNotEqual(cascade.original_tx_id_hex, cascade.tampered_tx_id_hex)
        self.assertEqual(cascade.downstream_broken_block_indices, (2, 3))

        # 1. Attempting to resolve only against Poisoned Fork C (length 4 vs active length 3)
        #    MUST reject Poisoned Fork C and keep main_ledger at length 3!
        outcome_poisoned = main_ledger.resolve_forks([poisoned_blocks])
        self.assertFalse(outcome_poisoned.switched_chain)
        self.assertEqual(outcome_poisoned.winning_chain_length, 3)
        self.assertEqual(outcome_poisoned.rejected_candidates_count, 1)

        # 2. Resolving against both Poisoned Fork C and valid Fork B (length 4)
        #    switches main_ledger to valid Fork B and updates UTXO balances!
        outcome_valid = main_ledger.resolve_forks([poisoned_blocks, fork_b.blocks])
        self.assertTrue(outcome_valid.switched_chain)
        self.assertEqual(outcome_valid.winning_chain_length, 4)
        self.assertEqual(outcome_valid.rejected_candidates_count, 1)
        self.assertEqual(main_ledger.get_balance(self.charlie.address), 60)  # 100 - 40
        self.assertEqual(main_ledger.get_balance(self.alice.address), 635)   # 695 - 100 + 40

    def test_worklet3_4_persistence_reload_and_on_disk_tamper_detection(self) -> None:
        """
        Worklet 3.4 & Pitfall 5:
        Persist the chain to disk, reload it with full Genesis re-validation, and
        verify that on-disk tampering is caught both by the file integrity seal AND
        by Genesis-to-tip cryptographic re-validation even if the seal is recomputed.
        """
        ledger = self._build_sample_ledger(difficulty=6)
        persistence = ChainPersistence(crypto_engine=self.engine, params=ledger.params)

        with tempfile.TemporaryDirectory() as tmpdir:
            chain_file = Path(tmpdir) / "ledger_chain.bclt"
            persistence.save_ledger(ledger, chain_file)

            # 1. Clean reload succeeds and reproduces exact balances
            reloaded = persistence.load_ledger(chain_file)
            self.assertEqual(reloaded.height, ledger.height)
            self.assertEqual(reloaded.tip.block_hash, ledger.tip.block_hash)
            self.assertEqual(
                reloaded.get_balance(self.alice.address),
                ledger.get_balance(self.alice.address),
            )
            self.assertEqual(
                reloaded.get_balance(self.bob.address),
                ledger.get_balance(self.bob.address),
            )

            # 2. Tamper Layer 1: Flip 1 byte in the middle of the on-disk file
            tampered_file_1 = Path(tmpdir) / "tampered_seal.bclt"
            raw_bytes = bytearray(chain_file.read_bytes())
            mid_idx = len(raw_bytes) // 2
            raw_bytes[mid_idx] ^= 0x01
            tampered_file_1.write_bytes(bytes(raw_bytes))

            with self.assertRaises(TamperDetectedError):
                persistence.load_ledger(tampered_file_1)

            # 3. Tamper Layer 2 (Pitfall 5 defense): Suppose an attacker with disk write
            #    access alters a transaction amount inside Block 1 AND recomputes the outer
            #    SHA-256 file seal so the file envelope checksum passes!
            #    Mandatory Genesis re-validation on reload MUST still catch the tampering!
            corrupted_blocks = list(ledger.blocks)
            b1 = corrupted_blocks[1]
            tx_coinbase = b1.transactions[0]
            inflated_coinbase = Transaction.create_coinbase(
                recipient_address=tx_coinbase.outputs[0].recipient_address,
                amount=999999,  # Inflated on disk!
                timestamp=tx_coinbase.timestamp,
            )
            corrupted_blocks[1] = Block(
                index=b1.index,
                previous_hash=b1.previous_hash,
                merkle_root=b1.merkle_root,
                timestamp=b1.timestamp,
                difficulty=b1.difficulty,
                nonce=b1.nonce,
                transactions=(inflated_coinbase, b1.transactions[1]),
                block_hash=b1.block_hash,
            )
            re_sealed_bytes = persistence.serialize_chain(
                blocks=corrupted_blocks,
                difficulty=ledger.difficulty,
                block_reward=ledger.block_reward,
            )
            tampered_file_2 = Path(tmpdir) / "tampered_resealed.bclt"
            tampered_file_2.write_bytes(re_sealed_bytes)

            with self.assertRaises(TamperDetectedError):
                persistence.load_ledger(tampered_file_2)

    def test_worklet3_5_difficulty_vs_mining_time_benchmark(self) -> None:
        rows = run_difficulty_benchmark(difficulties=(0, 4, 8), trials_per_difficulty=2)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0].difficulty_bits, 0)
        self.assertEqual(rows[0].theoretical_expected_hashes, 1)
        self.assertEqual(rows[1].difficulty_bits, 4)
        self.assertEqual(rows[1].theoretical_expected_hashes, 16)
        self.assertEqual(rows[2].difficulty_bits, 8)
        self.assertEqual(rows[2].theoretical_expected_hashes, 256)

        table_md = format_benchmark_markdown_table(rows)
        self.assertIn("Difficulty (Zero Bits)", table_md)
        self.assertIn("8 bits", table_md)





    def test_phase3_pinned_genesis_trust_anchor_catches_full_file_replacement(self) -> None:
        """
        Verify F-001 fix: If an attacker rewrites the entire .bclt file on disk starting
        from a newly mined fabricated Genesis block and recomputes the SHA-256 seal,
        loading with `expected_genesis_hash` detects and rejects the replacement.
        """
        honest_ledger = self._build_sample_ledger(difficulty=4)
        trusted_genesis_hash = honest_ledger.blocks[0].block_hash

        attacker_ledger = BlockchainLedger(difficulty=4, block_reward=50, crypto_engine=self.engine)
        attacker_ledger.create_genesis_block(
            initial_allocations=[(self.charlie.address, 9_000_000)],
            timestamp=1700009999,
        )

        persistence = ChainPersistence(crypto_engine=self.engine, params=honest_ledger.params)
        with tempfile.TemporaryDirectory() as tmpdir:
            ledger_file = Path(tmpdir) / "ledger.bclt"
            persistence.save_ledger(honest_ledger, ledger_file)

            # Honest reload with pinned genesis hash succeeds
            loaded = persistence.load_ledger(
                ledger_file, expected_genesis_hash=trusted_genesis_hash
            )
            self.assertEqual(loaded.blocks[0].block_hash, trusted_genesis_hash)

            # Attacker overwrites ledger.bclt with a completely valid, sealed chain
            # starting from attacker_ledger's Genesis block
            persistence.save_ledger(attacker_ledger, ledger_file)

            with self.assertRaises(TamperDetectedError):
                persistence.load_ledger(
                    ledger_file, expected_genesis_hash=trusted_genesis_hash
                )


    def test_phase4_equal_length_fork_tie_breaking_and_alien_genesis_rejection(self) -> None:
        """
        Verify F-001 & F-006 in BlockchainLedger.resolve_forks:
        1. Equal-length, equal-work valid fork retains the currently active chain (first-seen rule).
        2. Equal-length valid fork with strictly greater cumulative PoW work wins.
        3. Longer chain starting from an alien Genesis block is rejected.
        """
        ledger_a = self._build_sample_ledger(difficulty=4)
        self.assertEqual(ledger_a.height, 3)

        # 1. Equal-length (height=3), equal-difficulty (difficulty=4) competing branch:
        equal_fork = BlockchainLedger(difficulty=4, block_reward=50, crypto_engine=self.engine)
        equal_fork.load_verified_chain(ledger_a.blocks[:2])
        alt_tx = self.alice.create_signed_transfer(
            recipient_address=self.charlie.address,
            amount=50,
            spendable_utxos=equal_fork.get_spendable_utxos(self.alice.address),
            fee=0,
            timestamp=1700000500,
        )
        equal_fork.submit_transaction(alt_tx.to_bytes())
        equal_fork.mine_pending_transactions(
            miner_address=self.miner_wallet.address,
            timestamp=1700000505,
        )
        self.assertEqual(equal_fork.height, 3)

        outcome_tie = ledger_a.resolve_forks([equal_fork.blocks])
        self.assertFalse(outcome_tie.switched_chain)
        self.assertEqual(ledger_a.tip.block_hash, outcome_tie.winning_tip_hash_hex and bytes.fromhex(outcome_tie.winning_tip_hash_hex))

        # 2. Competing branch with strictly MORE cumulative work at the protocol difficulty
        #    (one extra block). Previously this test let a fork self-declare difficulty 6 on a
        #    difficulty-4 chain; that is exactly audit defect D1 and is now rejected.
        heavier_fork = BlockchainLedger(difficulty=4, block_reward=50, crypto_engine=self.engine)
        heavier_fork.load_verified_chain(ledger_a.blocks[:2])
        heavier_tx = self.alice.create_signed_transfer(
            recipient_address=self.charlie.address,
            amount=75,
            spendable_utxos=heavier_fork.get_spendable_utxos(self.alice.address),
            fee=0,
            timestamp=1700000600,
        )
        heavier_fork.submit_transaction(heavier_tx.to_bytes())
        heavier_fork.mine_pending_transactions(
            miner_address=self.miner_wallet.address,
            timestamp=1700000605,
        )
        heavier_fork.mine_pending_transactions(
            miner_address=self.miner_wallet.address,
            timestamp=1700000610,
        )
        self.assertEqual(heavier_fork.height, 4)

        # A same-length fork that merely CLAIMS a higher difficulty is rejected (D1).
        forged_tip = ProofOfWorkMiner().mine_block(
            index=2,
            previous_hash=ledger_a.blocks[1].block_hash,
            transactions=[Transaction.create_coinbase(self.charlie.address, 50, timestamp=2)],
            difficulty=6,
            timestamp=1700000700,
        )
        outcome_inflated = ledger_a.resolve_forks([list(ledger_a.blocks[:2]) + [forged_tip]])
        self.assertFalse(outcome_inflated.switched_chain)
        self.assertEqual(outcome_inflated.rejected_candidates_count, 1)

        outcome_heavier = ledger_a.resolve_forks([heavier_fork.blocks])
        self.assertTrue(outcome_heavier.switched_chain)
        self.assertEqual(ledger_a.tip.block_hash, heavier_fork.tip.block_hash)
        self.assertEqual(ledger_a.get_balance(self.charlie.address), 75)

        # 3. Longer chain (height=4) starting from an ALIEN Genesis block MUST be rejected!
        alien_ledger = BlockchainLedger(difficulty=4, block_reward=50, crypto_engine=self.engine)
        alien_ledger.create_genesis_block(
            initial_allocations=[(self.charlie.address, 5_000_000)],
            timestamp=1700009000,
        )
        for i in range(3):
            alien_ledger.mine_pending_transactions(
                miner_address=self.charlie.address,
                timestamp=1700009010 + i,
            )
        self.assertEqual(alien_ledger.height, 4)

        outcome_alien = ledger_a.resolve_forks([alien_ledger.blocks])
        self.assertFalse(outcome_alien.switched_chain)
        self.assertEqual(outcome_alien.rejected_candidates_count, 1)
        self.assertIn("Genesis block hash mismatch", outcome_alien.rejection_reasons[0])

    def test_phase4_excessive_coinbase_reward_rejected_and_state_unchanged(self) -> None:
        """Verify that a block minting more than block_reward + fees is rejected atomically."""
        from blockchain_lite.interfaces import ValidationError
        from blockchain_lite.ledger.pow import ProofOfWorkMiner

        ledger = BlockchainLedger(difficulty=4, block_reward=50, crypto_engine=self.engine)
        ledger.create_genesis_block(
            initial_allocations=[(self.alice.address, 1000)],
            timestamp=1700000000,
        )
        miner = ProofOfWorkMiner()
        greedy_coinbase = Transaction.create_coinbase(
            recipient_address=self.miner_wallet.address,
            amount=51,  # Exceeds allowed 50 reward (0 transfer fees)
            timestamp=1,  # correct height commitment, so only the reward cap is violated
        )
        greedy_block = miner.mine_block(
            index=1,
            previous_hash=ledger.tip.block_hash,
            transactions=[greedy_coinbase],
            difficulty=4,
            timestamp=1700000100,
        )
        with self.assertRaises(ValidationError):
            ledger.append_mined_block(greedy_block)
        self.assertEqual(ledger.height, 1)
        self.assertEqual(ledger.get_balance(self.miner_wallet.address), 0)


if __name__ == "__main__":
    unittest.main()
