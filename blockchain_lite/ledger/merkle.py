"""
Binary Merkle Tree & Inclusion Proof Engine (Worklet 2.2 & 2.3).

Satisfies:
- Worklet 2.2: "Build a Merkle tree over a block's transactions."
- Worklet 2.3: "Produce and verify Merkle inclusion proofs."
- Learning-outcome check 3: "What does a Merkle proof prove, and what is its
  size for N transactions?"
- Pitfall 2: "A Merkle tree that verifies the happy path but doesn't actually
  catch a swapped transaction — prove one altered byte breaks the root."
"""

from __future__ import annotations

import math
from typing import List, Optional, Sequence, Tuple

from blockchain_lite.crypto.hashing import default_hasher
from blockchain_lite.interfaces import (
    HASH_DIGEST_SIZE,
    MERKLE_INTERNAL_PREFIX,
    MERKLE_LEAF_PREFIX,
    HashInterface,
    MerkleProof,
    MerkleProofStep,
    SerializationError,
    ValidationError,
)
from blockchain_lite.models.transaction import Transaction
from blockchain_lite.serialization import ByteBuffer

DIRECTION_LEFT = "LEFT"
DIRECTION_RIGHT = "RIGHT"


def hash_merkle_leaf(tx_id: bytes, hasher: HashInterface = default_hasher) -> bytes:
    """
    Compute domain-separated leaf node hash: `H(0x00 || tx_id)`.
    Domain separation prevents second-preimage attacks where an attacker crafts
    a 64-byte transaction payload mimicking two concatenated 32-byte internal nodes.
    """
    if not isinstance(tx_id, bytes) or len(tx_id) != HASH_DIGEST_SIZE:
        raise ValidationError(f"Merkle leaf tx_id must be {HASH_DIGEST_SIZE} bytes")
    return hasher.hash_bytes(MERKLE_LEAF_PREFIX + tx_id)


def hash_merkle_internal(
    left_hash: bytes, right_hash: bytes, hasher: HashInterface = default_hasher
) -> bytes:
    """
    Compute domain-separated internal node hash: `H(0x01 || left_hash || right_hash)`.
    Non-commutative: `hash_merkle_internal(L, R) != hash_merkle_internal(R, L)` whenever `L != R`,
    ensuring swapped transactions produce a completely different parent hash and root.
    """
    if len(left_hash) != HASH_DIGEST_SIZE or len(right_hash) != HASH_DIGEST_SIZE:
        raise ValidationError("Merkle internal node children must be 32-byte hashes")
    return hasher.hash_bytes(MERKLE_INTERNAL_PREFIX + left_hash + right_hash)


class MerkleTree:
    """
    Complete Binary Merkle Tree over an ordered sequence of transaction IDs.

    Tree Construction Rules:
    1. Level 0 (leaves) consists of `[hash_merkle_leaf(tx_id) for tx_id in tx_ids]`.
    2. If `len(tx_ids) == 1`, the root is simply `levels[0][0]` (`hash_merkle_leaf(tx_ids[0])`),
       and the inclusion proof requires 0 sibling steps.
    3. At any level with `k > 1` nodes:
       - If `k` is odd, the trailing node is duplicated (`level + [level[-1]]`) to form
         `k + 1` even nodes before pairing adjacent `(left, right)` children via
         `hash_merkle_internal(left, right)`.
    4. Every inclusion proof records the leaf's original `tx_index` and the exact sequence
       of sibling hashes with their `LEFT` / `RIGHT` positions. During verification, both
       the directional flags AND their consistency with `tx_index`'s binary bit decomposition
       are checked, guaranteeing that swapping any two transactions breaks both the Merkle
       root and any position-bound inclusion proof.
    """

    def __init__(
        self,
        tx_ids: Sequence[bytes],
        hasher: HashInterface = default_hasher,
    ) -> None:
        if not tx_ids:
            raise ValidationError("Cannot build a MerkleTree over an empty transaction list")

        self._hasher = hasher
        self._tx_ids: Tuple[bytes, ...] = tuple(bytes(tid) for tid in tx_ids)
        for tid in self._tx_ids:
            if len(tid) != HASH_DIGEST_SIZE:
                raise ValidationError(
                    f"Each transaction ID in MerkleTree must be {HASH_DIGEST_SIZE} bytes"
                )

        self._levels: List[List[bytes]] = self._build_levels()

    @classmethod
    def from_transactions(
        cls,
        transactions: Sequence[Transaction],
        hasher: HashInterface = default_hasher,
    ) -> "MerkleTree":
        """Construct a `MerkleTree` directly from a sequence of `Transaction` objects."""
        if not transactions:
            raise ValidationError("Cannot build a MerkleTree from an empty transaction sequence")
        tx_ids = [tx.compute_tx_id(hasher=hasher) for tx in transactions]
        return cls(tx_ids=tx_ids, hasher=hasher)

    def _build_levels(self) -> List[List[bytes]]:
        leaves = [hash_merkle_leaf(tid, hasher=self._hasher) for tid in self._tx_ids]
        levels: List[List[bytes]] = [leaves]

        current = leaves
        while len(current) > 1:
            working = list(current)
            if len(working) % 2 == 1:
                working.append(working[-1])

            next_level: List[bytes] = []
            for i in range(0, len(working), 2):
                parent = hash_merkle_internal(
                    working[i], working[i + 1], hasher=self._hasher
                )
                next_level.append(parent)
            levels.append(next_level)
            current = next_level

        return levels

    # ------------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------------

    @property
    def leaf_count(self) -> int:
        return len(self._tx_ids)

    @property
    def height(self) -> int:
        """Number of internal hashing levels above the leaves (`ceil(log2(N))`)."""
        return len(self._levels) - 1

    @property
    def root(self) -> bytes:
        """32-byte Merkle root digest at the top of the tree."""
        return self._levels[-1][0]

    @property
    def root_hex(self) -> str:
        return self.root.hex()

    @property
    def levels(self) -> Tuple[Tuple[bytes, ...], ...]:
        return tuple(tuple(lvl) for lvl in self._levels)

    @staticmethod
    def expected_proof_length(num_transactions: int) -> int:
        """
        Learning-Outcome Check 3 Formula:
        For `N` transactions, the number of sibling hashes in an inclusion proof is:
        - `0` when `N == 1`
        - `ceil(log2(N))` when `N > 1`.
        """
        if num_transactions < 1:
            raise ValidationError("num_transactions must be >= 1")
        if num_transactions == 1:
            return 0
        return math.ceil(math.log2(num_transactions))

    # ------------------------------------------------------------------------
    # Inclusion Proof Generation & Verification (Worklet 2.3)
    # ------------------------------------------------------------------------

    def get_proof_by_index(self, tx_index: int) -> MerkleProof:
        """Generate an O(log2 N) `MerkleProof` for the transaction at `tx_index`."""
        if tx_index < 0 or tx_index >= len(self._tx_ids):
            raise ValidationError(
                f"tx_index {tx_index} out of bounds for Merkle tree with {len(self._tx_ids)} leaves"
            )

        steps: List[MerkleProofStep] = []
        idx = tx_index

        for level in self._levels[:-1]:
            working = list(level)
            if len(working) % 2 == 1:
                working.append(working[-1])

            if idx % 2 == 0:
                sibling_idx = idx + 1
                direction = DIRECTION_RIGHT
            else:
                sibling_idx = idx - 1
                direction = DIRECTION_LEFT

            steps.append(
                MerkleProofStep(
                    sibling_hash=working[sibling_idx],
                    direction=direction,
                )
            )
            idx //= 2

        return MerkleProof(
            tx_id=self._tx_ids[tx_index],
            tx_index=tx_index,
            merkle_root=self.root,
            steps=tuple(steps),
        )

    def get_proof(self, tx_id: bytes) -> MerkleProof:
        """Locate `tx_id` in the block's transactions and return its `MerkleProof`."""
        try:
            idx = self._tx_ids.index(tx_id)
        except ValueError as exc:
            raise ValidationError(
                f"Transaction {tx_id.hex()[:16]}... is not present in this MerkleTree"
            ) from exc
        return self.get_proof_by_index(idx)

    @staticmethod
    def verify_proof(
        proof: MerkleProof,
        expected_merkle_root: Optional[bytes] = None,
        hasher: HashInterface = default_hasher,
    ) -> bool:
        """
        Verify a `MerkleProof` in O(log2 N) hash evaluations without needing the full block.

        Checks:
        1. `proof.tx_id` and `proof.merkle_root` are valid 32-byte digests.
        2. If `expected_merkle_root` is provided (from a trusted block header),
           `proof.merkle_root` must match `expected_merkle_root`.
        3. At each step `s_i`, the direction flag (`LEFT` vs `RIGHT`) must match the
           parity of the running index `idx`:
           - If `idx` is even, the current node is a left child so its sibling MUST be `RIGHT`.
           - If `idx` is odd, the current node is a right child so its sibling MUST be `LEFT`.
           This prevents an attacker from claiming a transaction was at index `0` when it
           was actually swapped to index `1`!
        4. After consuming all steps, `idx` must have reduced to `0` (the root index),
           and the computed root hash must equal `proof.merkle_root`.
        """
        try:
            if (
                not isinstance(proof.tx_id, bytes)
                or len(proof.tx_id) != HASH_DIGEST_SIZE
                or not isinstance(proof.merkle_root, bytes)
                or len(proof.merkle_root) != HASH_DIGEST_SIZE
            ):
                return False

            if expected_merkle_root is not None and proof.merkle_root != expected_merkle_root:
                return False

            if proof.tx_index < 0:
                return False

            current_hash = hash_merkle_leaf(proof.tx_id, hasher=hasher)
            idx = proof.tx_index

            for step_idx, step in enumerate(proof.steps):
                if (
                    not isinstance(step.sibling_hash, bytes)
                    or len(step.sibling_hash) != HASH_DIGEST_SIZE
                ):
                    return False

                if idx % 2 == 0:
                    if step.direction != DIRECTION_RIGHT:
                        return False
                    current_hash = hash_merkle_internal(
                        current_hash, step.sibling_hash, hasher=hasher
                    )
                else:
                    if step.direction != DIRECTION_LEFT:
                        return False
                    # F-003 Guard: At the leaf level (step_idx == 0), distinct valid transactions
                    # have distinct leaf hashes. A left sibling equal to current_hash only occurs
                    # if an attacker is spoofing the duplicated phantom odd-tail index (tx_index == N).
                    if step_idx == 0 and step.sibling_hash == current_hash:
                        return False
                    current_hash = hash_merkle_internal(
                        step.sibling_hash, current_hash, hasher=hasher
                    )
                idx //= 2

            # After climbing to the root, the index must be 0
            if idx != 0:
                return False

            return current_hash == proof.merkle_root
        except (ValidationError, TypeError, ValueError):
            return False


# ============================================================================
# Canonical Serialization Helpers for MerkleProof
# ============================================================================

def serialize_merkle_proof(proof: MerkleProof) -> bytes:
    """Serialize a `MerkleProof` canonically into a `ByteBuffer`."""
    buf = ByteBuffer()
    buf.write_hash32(proof.tx_id)
    buf.write_uint32(proof.tx_index)
    buf.write_hash32(proof.merkle_root)
    buf.write_uint32(len(proof.steps))
    for step in proof.steps:
        dir_byte = 0 if step.direction == DIRECTION_LEFT else 1
        buf.write_uint8(dir_byte)
        buf.write_hash32(step.sibling_hash)
    return buf.to_bytes()


def deserialize_merkle_proof(data: bytes) -> MerkleProof:
    """Deserialize a `MerkleProof` from canonical bytes."""
    reader = ByteBuffer(data)
    tx_id = reader.read_hash32()
    tx_index = reader.read_uint32()
    merkle_root = reader.read_hash32()
    step_count = reader.read_uint32()
    if step_count > 64:
        raise SerializationError(f"Unreasonable Merkle proof depth: {step_count}")

    steps: List[MerkleProofStep] = []
    for _ in range(step_count):
        dir_byte = reader.read_uint8()
        if dir_byte not in (0, 1):
            raise SerializationError(f"Invalid Merkle step direction byte: {dir_byte}")
        direction = DIRECTION_LEFT if dir_byte == 0 else DIRECTION_RIGHT
        sibling = reader.read_hash32()
        steps.append(MerkleProofStep(sibling_hash=sibling, direction=direction))

    reader.assert_exhausted()
    return MerkleProof(
        tx_id=tx_id,
        tx_index=tx_index,
        merkle_root=merkle_root,
        steps=tuple(steps),
    )
