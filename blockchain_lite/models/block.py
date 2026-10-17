"""
Block Model & Predecessor-Hash Chaining (Worklet 2.1).

Satisfies:
- Worklet 2.1: "Build a block (transactions, previous-hash, nonce) and chain
  blocks by predecessor hash."
- Learning-outcome check 4: "Why does the previous-hash link make the chain
  tamper-evident?"
- Pitfall 3: "Treating the previous-hash link as decoration; if you can edit a
  middle block without the chain noticing, it isn't tamper-evident."
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from blockchain_lite.crypto.hashing import default_hasher
from blockchain_lite.interfaces import (
    HASH_DIGEST_SIZE,
    MAX_UINT32,
    MAX_UINT64,
    CanonicalSerializable,
    HashInterface,
    MerkleProof,
    SerializationError,
    TamperDetectedError,
    ValidationError,
)
from blockchain_lite.ledger.merkle import MerkleTree
from blockchain_lite.models.transaction import Transaction
from blockchain_lite.serialization import ByteBuffer

BLOCK_HEADER_BYTE_SIZE: int = 4 + 32 + 32 + 8 + 4 + 8  # 88 bytes fixed


@dataclass(frozen=True)
class BlockHeader:
    """The 88-byte PoW header on its own: what an SPV (light) client downloads."""

    index: int
    previous_hash: bytes
    merkle_root: bytes
    timestamp: int
    difficulty: int
    nonce: int

    SIZE = 88

    @classmethod
    def from_bytes(cls, data: bytes) -> "BlockHeader":
        if len(data) != cls.SIZE:
            raise SerializationError(f"Block header must be {cls.SIZE} bytes, got {len(data)}")
        reader = ByteBuffer(data)
        header = cls(
            index=reader.read_uint32(),
            previous_hash=reader.read_hash32(),
            merkle_root=reader.read_hash32(),
            timestamp=reader.read_uint64(),
            difficulty=reader.read_uint32(),
            nonce=reader.read_uint64(),
        )
        reader.assert_exhausted()
        return header

    def to_bytes(self) -> bytes:
        prefix = Block.pack_header_prefix(
            self.index, self.previous_hash, self.merkle_root, self.timestamp, self.difficulty
        )
        buf = ByteBuffer(prefix)
        buf.write_uint64(self.nonce)
        return buf.to_bytes()

    def compute_hash(self, hasher: HashInterface = default_hasher) -> bytes:
        return hasher.hash_bytes(self.to_bytes())


@dataclass(frozen=True)
class Block(CanonicalSerializable):
    """
    Immutable Block in the Blockchain-Lite ledger.

    Header Fields (committed to by the 88-byte PoW `block_hash`):
    - `index` (`uint32`, 4B): Block height (`0` for Genesis, `prev.index + 1` thereafter).
    - `previous_hash` (`bytes32`, 32B): Header hash of block `index - 1` (`0x00..00` for Genesis).
    - `merkle_root` (`bytes32`, 32B): Binary Merkle root committing to all `transactions`.
    - `timestamp` (`uint64`, 8B): Unix epoch timestamp in seconds.
    - `difficulty` (`uint32`, 4B): Required number of leading zero bits in `block_hash` (`0..256`).
    - `nonce` (`uint64`, 8B): Proof-of-Work counter solved during mining.

    Body & Identity Fields:
    - `transactions` (`Tuple[Transaction, ...]`): Ordered list of block transactions.
    - `block_hash` (`bytes32`, 32B): `SHA256(header_bytes)`.
    """

    index: int
    previous_hash: bytes
    merkle_root: bytes
    timestamp: int
    difficulty: int
    nonce: int
    transactions: Tuple[Transaction, ...]
    block_hash: bytes

    def __post_init__(self) -> None:
        if isinstance(self.index, bool) or not isinstance(self.index, int):
            raise ValidationError("Block.index must be an integer")
        if self.index < 0 or self.index > MAX_UINT32:
            raise ValidationError(f"Block.index out of uint32 range: {self.index}")

        if not isinstance(self.previous_hash, bytes) or len(self.previous_hash) != HASH_DIGEST_SIZE:
            raise ValidationError("Block.previous_hash must be 32 bytes")
        if not isinstance(self.merkle_root, bytes) or len(self.merkle_root) != HASH_DIGEST_SIZE:
            raise ValidationError("Block.merkle_root must be 32 bytes")
        if not isinstance(self.block_hash, bytes) or len(self.block_hash) != HASH_DIGEST_SIZE:
            raise ValidationError("Block.block_hash must be 32 bytes")

        if isinstance(self.timestamp, bool) or not isinstance(self.timestamp, int):
            raise ValidationError("Block.timestamp must be an integer")
        if self.timestamp < 0 or self.timestamp > MAX_UINT64:
            raise ValidationError(f"Block.timestamp out of uint64 range: {self.timestamp}")

        if isinstance(self.difficulty, bool) or not isinstance(self.difficulty, int):
            raise ValidationError("Block.difficulty must be an integer")
        if self.difficulty < 0 or self.difficulty > 256:
            raise ValidationError(f"Block.difficulty must be in [0, 256], got {self.difficulty}")

        if isinstance(self.nonce, bool) or not isinstance(self.nonce, int):
            raise ValidationError("Block.nonce must be an integer")
        if self.nonce < 0 or self.nonce > MAX_UINT64:
            raise ValidationError(f"Block.nonce out of uint64 range: {self.nonce}")

        if not isinstance(self.transactions, tuple):
            object.__setattr__(self, "transactions", tuple(self.transactions))
        if len(self.transactions) == 0:
            raise ValidationError("Block must contain at least one transaction")
        for tx in self.transactions:
            if not isinstance(tx, Transaction):
                raise ValidationError("All elements of Block.transactions must be Transaction objects")

    # ------------------------------------------------------------------------
    # Header Serialization & Hashing
    # ------------------------------------------------------------------------

    @staticmethod
    def pack_header_prefix(
        index: int,
        previous_hash: bytes,
        merkle_root: bytes,
        timestamp: int,
        difficulty: int,
    ) -> bytes:
        """
        Pack the 80-byte static prefix of the block header (everything before `nonce`).
        Used by the Proof-of-Work miner to avoid re-serializing static fields on each nonce trial.
        """
        buf = ByteBuffer()
        buf.write_uint32(index)
        buf.write_hash32(previous_hash)
        buf.write_hash32(merkle_root)
        buf.write_uint64(timestamp)
        buf.write_uint32(difficulty)
        return buf.to_bytes()

    def header_bytes(self, nonce_override: Optional[int] = None) -> bytes:
        """Return the canonical 88-byte block header."""
        nonce_val = self.nonce if nonce_override is None else nonce_override
        buf = ByteBuffer()
        buf.write_uint32(self.index)
        buf.write_hash32(self.previous_hash)
        buf.write_hash32(self.merkle_root)
        buf.write_uint64(self.timestamp)
        buf.write_uint32(self.difficulty)
        buf.write_uint64(nonce_val)
        return buf.to_bytes()

    def compute_header_hash(
        self,
        nonce_override: Optional[int] = None,
        hasher: HashInterface = default_hasher,
    ) -> bytes:
        """Compute the 32-byte SHA-256 digest of the canonical 88-byte block header."""
        return hasher.hash_bytes(self.header_bytes(nonce_override=nonce_override))

    def compute_merkle_tree(self, hasher: HashInterface = default_hasher) -> MerkleTree:
        """Construct the binary `MerkleTree` over this block's transactions."""
        return MerkleTree.from_transactions(self.transactions, hasher=hasher)

    def compute_merkle_root(self, hasher: HashInterface = default_hasher) -> bytes:
        """Recompute the 32-byte Merkle root directly from `self.transactions`."""
        return self.compute_merkle_tree(hasher=hasher).root

    def generate_merkle_proof(
        self, tx_id: bytes, hasher: HashInterface = default_hasher
    ) -> MerkleProof:
        """Generate a Merkle inclusion proof for `tx_id` within this block."""
        tree = self.compute_merkle_tree(hasher=hasher)
        return tree.get_proof(tx_id)

    @property
    def block_hash_hex(self) -> str:
        return self.block_hash.hex()

    @property
    def previous_hash_hex(self) -> str:
        return self.previous_hash.hex()

    @property
    def merkle_root_hex(self) -> str:
        return self.merkle_root.hex()

    # ------------------------------------------------------------------------
    # Integrity Verification
    # ------------------------------------------------------------------------

    def verify_crystallized_integrity(
        self, hasher: HashInterface = default_hasher
    ) -> None:
        """
        Verify that:
        1. Recomputing the Merkle tree over `self.transactions` matches `self.merkle_root`.
        2. Recomputing the header hash over `(index, previous_hash, merkle_root, timestamp,
           difficulty, nonce)` matches `self.block_hash`.
        Raises `TamperDetectedError` if either check fails.
        """
        recomputed_merkle = self.compute_merkle_root(hasher=hasher)
        if recomputed_merkle != self.merkle_root:
            raise TamperDetectedError(
                f"Block #{self.index} Merkle root mismatch: "
                f"header claims {self.merkle_root_hex[:16]}..., "
                f"but transactions hash to {recomputed_merkle.hex()[:16]}..."
            )

        recomputed_hash = self.compute_header_hash(hasher=hasher)
        if recomputed_hash != self.block_hash:
            raise TamperDetectedError(
                f"Block #{self.index} header hash mismatch: "
                f"stored {self.block_hash_hex[:16]}..., "
                f"recomputed {recomputed_hash.hex()[:16]}..."
            )

    # ------------------------------------------------------------------------
    # Canonical Serialization (Header + Transactions + Stored Block Hash)
    # ------------------------------------------------------------------------

    def write_to_buffer(self, buf: ByteBuffer) -> None:
        buf.write_uint32(self.index)
        buf.write_hash32(self.previous_hash)
        buf.write_hash32(self.merkle_root)
        buf.write_uint64(self.timestamp)
        buf.write_uint32(self.difficulty)
        buf.write_uint64(self.nonce)
        buf.write_hash32(self.block_hash)
        buf.write_uint32(len(self.transactions))
        for tx in self.transactions:
            tx.write_to_buffer(buf)

    def to_bytes(self) -> bytes:
        buf = ByteBuffer()
        self.write_to_buffer(buf)
        return buf.to_bytes()

    @classmethod
    def read_from_buffer(cls, reader: ByteBuffer) -> "Block":
        index = reader.read_uint32()
        previous_hash = reader.read_hash32()
        merkle_root = reader.read_hash32()
        timestamp = reader.read_uint64()
        difficulty = reader.read_uint32()
        nonce = reader.read_uint64()
        block_hash = reader.read_hash32()
        tx_count = reader.read_uint32()
        if tx_count == 0 or tx_count > 100_000:
            raise SerializationError(f"Invalid block transaction count: {tx_count}")
        transactions = tuple(Transaction.read_from_buffer(reader) for _ in range(tx_count))
        return cls(
            index=index,
            previous_hash=previous_hash,
            merkle_root=merkle_root,
            timestamp=timestamp,
            difficulty=difficulty,
            nonce=nonce,
            transactions=transactions,
            block_hash=block_hash,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "Block":
        try:
            reader = ByteBuffer(data)
            block = cls.read_from_buffer(reader)
            reader.assert_exhausted()
            return block
        except ValidationError as exc:
            raise SerializationError(f"Invalid block in canonical bytes: {exc}") from exc


