"""
Full-Chain Genesis-to-Tip Validator & Tamper Cascade Tracer (Worklet 3.1 & 3.2).

Satisfies:
- Worklet 3.1: "Validate a full chain (hashes, signatures, Merkle roots) from genesis."
- Worklet 3.2: "show one altered transaction invalidates the rest."
- Learning-outcome check 2: "Change one byte of one transaction — trace exactly
  what breaks and why."
"""

from __future__ import annotations

import time
from dataclasses import dataclass, replace
from typing import Dict, Optional, Sequence, Tuple

from blockchain_lite.crypto.asymmetric import default_crypto_engine
from blockchain_lite.crypto.hashing import default_hasher
from blockchain_lite.interfaces import (
    GENESIS_PREV_HASH,
    HASH_DIGEST_SIZE,
    AsymmetricCryptoInterface,
    HashInterface,
    TamperDetectedError,
    ValidationError,
)
from blockchain_lite.ledger.consensus import ConsensusParams, check_block_consensus
from blockchain_lite.ledger.pow import verify_block_pow
from blockchain_lite.ledger.utxo import UTXOSet
from blockchain_lite.models.block import Block


@dataclass(frozen=True)
class ChainValidationReport:
    """
    Summary produced when a blockchain is validated from Genesis (`block 0`) to tip.
    """
    is_valid: bool
    block_count: int
    total_transactions: int
    cumulative_pow_work: int
    utxo_set: UTXOSet
    error_message: str = ""
    failed_block_index: Optional[int] = None


@dataclass(frozen=True)
class TamperCascadeReport:
    """
    Detailed step-by-step diagnostic trace for Learning-Outcome Check 2 & Worklet 3.2:
    Shows every cryptographic link that breaks when 1 byte of a transaction inside
    block `tampered_block_index` is modified.
    """
    tampered_block_index: int
    tampered_tx_index: int
    original_tx_id_hex: str
    tampered_tx_id_hex: str
    signature_valid_after_tamper: bool
    original_merkle_root_hex: str
    recomputed_merkle_root_hex: str
    merkle_root_matches_header: bool
    original_block_hash_hex: str
    recomputed_block_hash_If_merkle_updated_hex: str
    downstream_broken_block_indices: Tuple[int, ...]


class FullChainValidator:
    """
    Stateless verifier that validates an entire sequence of blocks from the Genesis
    block (`index 0`), checking:
    1. Genesis block `index == 0`, `previous_hash == 0x00...00`, and (when a trusted
       Genesis anchor `expected_genesis_hash` is provided) `block_hash == expected_genesis_hash`.
    2. Sequential block indices (`block[i].index == i`).
    3. Predecessor hash links (`block[i].previous_hash == block[i-1].block_hash`).
    4. Crystallized block integrity (`merkle_root == MerkleTree(txs).root` and
       `block_hash == SHA256(header)`).
    5. Proof-of-Work difficulty target satisfaction (`int(block_hash) < 2^(256 - difficulty)`),
       where `difficulty` must equal the schedule in `consensus.expected_difficulty`, plus
       timestamp bounds and the coinbase height commitment (`consensus.check_block_consensus`).
    6. Every transaction's RSA signatures, UTXO existence, public-key ownership,
       absence of intra-block or cross-block double-spending, and conservation of value.
    """

    def __init__(
        self,
        crypto_engine: AsymmetricCryptoInterface = default_crypto_engine,
        hasher: HashInterface = default_hasher,
        max_block_reward: Optional[int] = None,
        expected_genesis_hash: Optional[bytes] = None,
        checkpoints: Optional[Dict[int, bytes]] = None,
        params: Optional[ConsensusParams] = None,
    ) -> None:
        params = params or ConsensusParams()
        if max_block_reward is not None:
            params = replace(params, block_reward=max_block_reward)
        if expected_genesis_hash is not None and (
            not isinstance(expected_genesis_hash, bytes)
            or len(expected_genesis_hash) != HASH_DIGEST_SIZE
        ):
            raise ValidationError("expected_genesis_hash must be a 32-byte digest")
        self._crypto_engine = crypto_engine
        self._hasher = hasher
        self._params = params
        self._expected_genesis_hash = expected_genesis_hash
        self._checkpoints: Dict[int, bytes] = dict(checkpoints) if checkpoints else {}

    @property
    def params(self) -> ConsensusParams:
        return self._params

    @property
    def checkpoints(self) -> Dict[int, bytes]:
        return dict(self._checkpoints)

    def register_checkpoint(self, block_index: int, block_hash: bytes) -> None:
        """Register a trusted checkpoint hash for a given block height."""
        if not isinstance(block_index, int) or block_index < 0:
            raise ValidationError("Checkpoint block index must be a non-negative integer")
        if not isinstance(block_hash, bytes) or len(block_hash) != HASH_DIGEST_SIZE:
            raise ValidationError("Checkpoint block hash must be 32 bytes")
        self._checkpoints[block_index] = block_hash

    def validate_chain_or_raise(
        self,
        blocks: Sequence[Block],
        expected_genesis_hash: Optional[bytes] = None,
    ) -> Tuple[UTXOSet, int]:
        """
        Validate `blocks` from Genesis to tip.
        Returns `(final_utxo_set, cumulative_pow_work)` if valid.
        Raises `TamperDetectedError`, `DoubleSpendError`, or `ValidationError` on failure.
        """
        if not blocks:
            raise ValidationError("Blockchain cannot be empty (missing Genesis block)")

        pinned_genesis = (
            expected_genesis_hash
            if expected_genesis_hash is not None
            else self._expected_genesis_hash
        )

        utxo_set = UTXOSet()
        cumulative_work = 0
        now = int(time.time())

        expected_idx = 0
        try:
            for expected_idx, block in enumerate(blocks):
                if block.index != expected_idx:
                    raise ValidationError(
                        f"Block index discontinuity: expected index {expected_idx}, got {block.index}"
                    )

                if expected_idx == 0:
                    if block.previous_hash != GENESIS_PREV_HASH:
                        raise TamperDetectedError(
                            f"Genesis block (index 0) has non-zero previous_hash: {block.previous_hash_hex}"
                        )
                    if pinned_genesis is not None and block.block_hash != pinned_genesis:
                        raise TamperDetectedError(
                            f"Genesis block hash mismatch against trusted Genesis anchor: "
                            f"expected {pinned_genesis.hex()[:16]}..., got {block.block_hash_hex[:16]}..."
                        )
                else:
                    prev_block = blocks[expected_idx - 1]
                    if block.previous_hash != prev_block.block_hash:
                        raise TamperDetectedError(
                            f"Broken chain link at Block #{block.index}: "
                            f"previous_hash ({block.previous_hash_hex[:16]}...) does not match "
                            f"Block #{prev_block.index} hash ({prev_block.block_hash_hex[:16]}...)"
                        )

                # Checkpoint verification
                if block.index in self._checkpoints:
                    expected_cp = self._checkpoints[block.index]
                    if block.block_hash != expected_cp:
                        raise TamperDetectedError(
                            f"Checkpoint mismatch at Block #{block.index}: "
                            f"expected {expected_cp.hex()[:16]}..., got {block.block_hash_hex[:16]}..."
                        )

                # Verify Merkle root and block header hash
                block.verify_crystallized_integrity(hasher=self._hasher)

                # Verify Proof-of-Work difficulty target
                verify_block_pow(block, hasher=self._hasher)

                # Difficulty schedule, timestamp bounds, coinbase height (D1/D3/D8)
                check_block_consensus(block, blocks[:expected_idx], self._params, now)

                # Validate and apply all transactions against the running UTXO set
                utxo_set.apply_block(
                    block,
                    max_block_reward=self._params.block_reward,
                    crypto_engine=self._crypto_engine,
                    hasher=self._hasher,
                )

                # Each block contributes 2^(difficulty) expected hash work
                cumulative_work += 1 << block.difficulty
        except ValidationError as exc:
            # Expose the failing height so callers never re-validate prefixes.
            exc.failed_block_index = expected_idx  # type: ignore[attr-defined]
            raise

        return utxo_set, cumulative_work

    def validate_chain(
        self,
        blocks: Sequence[Block],
        expected_genesis_hash: Optional[bytes] = None,
    ) -> ChainValidationReport:
        """
        Non-throwing wrapper around `validate_chain_or_raise` returning a structured
        `ChainValidationReport`.
        """
        try:
            utxo_set, work = self.validate_chain_or_raise(
                blocks, expected_genesis_hash=expected_genesis_hash
            )
            total_txs = sum(len(b.transactions) for b in blocks)
            return ChainValidationReport(
                is_valid=True,
                block_count=len(blocks),
                total_transactions=total_txs,
                cumulative_pow_work=work,
                utxo_set=utxo_set,
            )
        except ValidationError as exc:
            failed_idx: Optional[int] = getattr(exc, "failed_block_index", None)
            return ChainValidationReport(
                is_valid=False,
                block_count=len(blocks),
                total_transactions=sum(len(b.transactions) for b in blocks),
                cumulative_pow_work=0,
                utxo_set=UTXOSet(),
                error_message=str(exc),
                failed_block_index=failed_idx,
            )

    def trace_tamper_cascade(
        self,
        original_chain: Sequence[Block],
        tampered_chain: Sequence[Block],
        block_index: int,
        tx_index: int = 0,
    ) -> TamperCascadeReport:
        """
        Produce a complete mathematical trace showing what breaks when a transaction
        at `(block_index, tx_index)` is tampered with.
        """
        orig_block = original_chain[block_index]
        tamp_block = tampered_chain[block_index]

        orig_tx = orig_block.transactions[tx_index]
        tamp_tx = tamp_block.transactions[tx_index]

        sig_ok = tamp_tx.verify_signatures(crypto_engine=self._crypto_engine)
        recomputed_merkle = tamp_block.compute_merkle_root(hasher=self._hasher)
        merkle_matches = recomputed_merkle == tamp_block.merkle_root

        hypothetical_block = Block(
            index=tamp_block.index,
            previous_hash=tamp_block.previous_hash,
            merkle_root=recomputed_merkle,
            timestamp=tamp_block.timestamp,
            difficulty=tamp_block.difficulty,
            nonce=tamp_block.nonce,
            transactions=tamp_block.transactions,
            block_hash=tamp_block.block_hash,
        )
        recomputed_header_hash = hypothetical_block.compute_header_hash(hasher=self._hasher)

        downstream = tuple(range(block_index + 1, len(tampered_chain)))

        return TamperCascadeReport(
            tampered_block_index=block_index,
            tampered_tx_index=tx_index,
            original_tx_id_hex=orig_tx.compute_tx_id(self._hasher).hex(),
            tampered_tx_id_hex=tamp_tx.compute_tx_id(self._hasher).hex(),
            signature_valid_after_tamper=sig_ok,
            original_merkle_root_hex=orig_block.merkle_root_hex,
            recomputed_merkle_root_hex=recomputed_merkle.hex(),
            merkle_root_matches_header=merkle_matches,
            original_block_hash_hex=orig_block.block_hash_hex,
            recomputed_block_hash_If_merkle_updated_hex=recomputed_header_hash.hex(),
            downstream_broken_block_indices=downstream,
        )
