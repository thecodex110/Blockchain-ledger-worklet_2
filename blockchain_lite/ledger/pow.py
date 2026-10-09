"""
Proof-of-Work (PoW) Mining & Difficulty Verification Engine (Worklet 2.5).

Satisfies:
- Algorithms: "Proof-of-work (nonce search)"
- Data structures: "Nonce search ordered by difficulty"
- Worklet 2.5: "Implement proof-of-work with adjustable difficulty."
- Learning-outcome check 5: "Distinguish what a signature guarantees from what
  proof-of-work guarantees."
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from typing import Optional, Sequence, Tuple

from blockchain_lite.crypto.hashing import default_hasher
from blockchain_lite.interfaces import (
    HASH_DIGEST_SIZE,
    MAX_UINT64,
    HashInterface,
    TamperDetectedError,
    ValidationError,
)
from blockchain_lite.ledger.merkle import MerkleTree
from blockchain_lite.models.block import Block
from blockchain_lite.models.transaction import Transaction


@dataclass(frozen=True)
class MiningStats:
    """
    Empirical telemetry returned when a block is mined via Proof-of-Work.
    Used in Worklet 3.5 to measure how adjustable difficulty affects mining time.
    """
    block_index: int
    difficulty_bits: int
    winning_nonce: int
    hashes_tried: int
    elapsed_seconds: float
    hashes_per_second: float
    block_hash_hex: str


def count_leading_zero_bits(digest: bytes) -> int:
    """
    Count the exact number of leading '0' bits in a 32-byte (256-bit) digest
    viewed in big-endian bit order.
    """
    if len(digest) != HASH_DIGEST_SIZE:
        raise ValidationError(f"Digest must be {HASH_DIGEST_SIZE} bytes")
    as_int = int.from_bytes(digest, byteorder="big", signed=False)
    if as_int == 0:
        return 256
    return 256 - as_int.bit_length()


def target_for_difficulty(difficulty_bits: int) -> int:
    """
    Compute the 256-bit numeric threshold `T(D) = 2^(256 - D)` for `difficulty_bits`
    leading zero bits (`0 <= D <= 256`).
    A 256-bit digest satisfies difficulty `D` iff `int(digest) < T(D)`.
    """
    if isinstance(difficulty_bits, bool) or not isinstance(difficulty_bits, int):
        raise ValidationError("difficulty_bits must be an integer")
    if difficulty_bits < 0 or difficulty_bits > 256:
        raise ValidationError(f"difficulty_bits must be in [0, 256], got {difficulty_bits}")
    return 1 << (256 - difficulty_bits)


def hash_meets_difficulty(digest: bytes, difficulty_bits: int) -> bool:
    """
    Verify in O(1) time whether `digest` has at least `difficulty_bits` leading zero bits.
    """
    if len(digest) != HASH_DIGEST_SIZE:
        return False
    threshold = target_for_difficulty(difficulty_bits)
    digest_int = int.from_bytes(digest, byteorder="big", signed=False)
    return digest_int < threshold


def verify_block_pow(block: Block, hasher: HashInterface = default_hasher) -> None:
    """
    Verify that a `Block`'s header hash matches its header fields AND satisfies
    its claimed `block.difficulty` target.
    Raises `TamperDetectedError` if the hash is forged or does not meet difficulty.
    """
    recomputed = block.compute_header_hash(hasher=hasher)
    if recomputed != block.block_hash:
        raise TamperDetectedError(
            f"Block #{block.index} header hash mismatch: stored {block.block_hash_hex[:16]}..., "
            f"recomputed {recomputed.hex()[:16]}..."
        )
    if not hash_meets_difficulty(block.block_hash, block.difficulty):
        actual_zeros = count_leading_zero_bits(block.block_hash)
        raise TamperDetectedError(
            f"Block #{block.index} fails Proof-of-Work target: requires >= {block.difficulty} "
            f"leading zero bits, but hash {block.block_hash_hex[:16]}... has only {actual_zeros}"
        )


class ProofOfWorkMiner:
    """
    Adjustable-Difficulty Proof-of-Work Nonce Search Engine.

    How Nonce Search Works:
    - Given block metadata (`index`, `previous_hash`, `transactions`, `difficulty`, `timestamp`),
      first compute the deterministic 32-byte `merkle_root` over `transactions`.
    - Pack the static 80-byte header prefix `[index][previous_hash][merkle_root][timestamp][difficulty]`.
    - Iterate `nonce = start_nonce, start_nonce + 1, ...` appending `struct.pack(">Q", nonce)`
      and evaluating `H(header_88_bytes)` until `int(digest) < 2^(256 - difficulty)`.
    """

    def __init__(self, hasher: HashInterface = default_hasher) -> None:
        self._hasher = hasher

    def mine_block_with_stats(
        self,
        index: int,
        previous_hash: bytes,
        transactions: Sequence[Transaction],
        difficulty: int = 8,
        timestamp: Optional[int] = None,
        start_nonce: int = 0,
        max_attempts: int = 10_000_000,
    ) -> Tuple[Block, MiningStats]:
        if not transactions:
            raise ValidationError("Cannot mine a block with zero transactions")
        if start_nonce < 0 or start_nonce > MAX_UINT64:
            raise ValidationError(f"Invalid start_nonce: {start_nonce}")
        if max_attempts < 1:
            raise ValidationError(f"max_attempts must be >= 1, got {max_attempts}")

        block_ts = int(time.time()) if timestamp is None else timestamp
        tx_tuple = tuple(transactions)
        merkle_root = MerkleTree.from_transactions(tx_tuple, hasher=self._hasher).root

        prefix_80 = Block.pack_header_prefix(
            index=index,
            previous_hash=previous_hash,
            merkle_root=merkle_root,
            timestamp=block_ts,
            difficulty=difficulty,
        )
        threshold = target_for_difficulty(difficulty)

        t_start = time.perf_counter()
        nonce = start_nonce
        hashes_tried = 0

        for _ in range(max_attempts):
            header_bytes = prefix_80 + struct.pack(">Q", nonce)
            digest = self._hasher.hash_bytes(header_bytes)
            hashes_tried += 1

            if int.from_bytes(digest, byteorder="big", signed=False) < threshold:
                elapsed = max(time.perf_counter() - t_start, 1e-9)
                mined_block = Block(
                    index=index,
                    previous_hash=previous_hash,
                    merkle_root=merkle_root,
                    timestamp=block_ts,
                    difficulty=difficulty,
                    nonce=nonce,
                    transactions=tx_tuple,
                    block_hash=digest,
                )
                stats = MiningStats(
                    block_index=index,
                    difficulty_bits=difficulty,
                    winning_nonce=nonce,
                    hashes_tried=hashes_tried,
                    elapsed_seconds=elapsed,
                    hashes_per_second=hashes_tried / elapsed,
                    block_hash_hex=digest.hex(),
                )
                return mined_block, stats

            nonce = (nonce + 1) & MAX_UINT64

        raise ValidationError(
            f"Proof-of-Work nonce search exhausted {max_attempts} attempts at difficulty {difficulty}"
        )

    def mine_block(
        self,
        index: int,
        previous_hash: bytes,
        transactions: Sequence[Transaction],
        difficulty: int = 8,
        timestamp: Optional[int] = None,
        start_nonce: int = 0,
        max_attempts: int = 10_000_000,
    ) -> Block:
        """Mine and return a valid `Block` satisfying `difficulty` leading zero bits."""
        block, _ = self.mine_block_with_stats(
            index=index,
            previous_hash=previous_hash,
            transactions=transactions,
            difficulty=difficulty,
            timestamp=timestamp,
            start_nonce=start_nonce,
            max_attempts=max_attempts,
        )
        return block


default_miner = ProofOfWorkMiner()
