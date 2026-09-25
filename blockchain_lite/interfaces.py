"""
Cross-Worklet Interface Definitions, Domain Constants, and Exceptions.

Per Guidelines Section 4 & 5:
"Interface definitions for each worklet are therefore crucial, and must be defined
as part of the initial design. The three worklets finally integrate to create a
working demonstration."
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

# ============================================================================
# System-Wide Protocol & Domain Constants
# ============================================================================

PROTOCOL_MAGIC: bytes = b"BCLT"  # 4-byte file/network magic header ("Blockchain-Lite")
PROTOCOL_VERSION: int = 1

HASH_DIGEST_SIZE: int = 32  # 256-bit (32-byte) digest for all hashes & addresses
GENESIS_PREV_HASH: bytes = b"\x00" * HASH_DIGEST_SIZE

# Transaction Types
TX_TYPE_COINBASE: int = 0
TX_TYPE_TRANSFER: int = 1

# Maximum Safe Integer Amount (prevents uint64 overflow during summation)
MAX_UINT8: int = (1 << 8) - 1
MAX_UINT32: int = (1 << 32) - 1
MAX_UINT64: int = (1 << 64) - 1
MAX_TOKEN_SUPPLY: int = 10_000_000_000_000_000  # 10^16 integer units

# Merkle Tree Domain Separation Prefixes (mitigates THR-06 second-preimage attacks)
MERKLE_LEAF_PREFIX: bytes = b"\x00"
MERKLE_INTERNAL_PREFIX: bytes = b"\x01"
MERKLE_EMPTY_HASH: bytes = b"\x00" * HASH_DIGEST_SIZE


# ============================================================================
# Domain Exceptions
# ============================================================================

class BlockchainLiteError(Exception):
    """Base exception for all Blockchain-Lite errors."""


class SerializationError(BlockchainLiteError):
    """Raised when canonical byte serialization or deserialization fails."""


class CryptoError(BlockchainLiteError):
    """Raised when key generation, signing, or cryptographic verification fails."""


class ValidationError(BlockchainLiteError):
    """Raised when a transaction, Merkle proof, or block fails validation."""


class DoubleSpendError(ValidationError):
    """Raised when a transaction or block attempts to spend an already-spent UTXO."""


class TamperDetectedError(ValidationError):
    """Raised when in-memory or on-disk tampering is detected during verification."""


# ============================================================================
# Shared Data Transfer Structures
# ============================================================================

@dataclass(frozen=True)
class AvalancheReport:
    """
    Captures the bit-level behaviour of the hash function when an input is modified
    (Digital Logic & Computer Organization learning outcome check).
    """
    original_input: bytes
    modified_input: bytes
    original_digest_hex: str
    modified_digest_hex: str
    input_bits_flipped: int
    output_bits_flipped: int
    total_output_bits: int
    flip_ratio: float
    differing_byte_indices: Tuple[int, ...]


@dataclass(frozen=True)
class MerkleProofStep:
    """
    Single step in an O(log2 N) Merkle inclusion proof.
    `direction` indicates whether `sibling_hash` is concatenated on the 'LEFT' or 'RIGHT'.
    """
    sibling_hash: bytes
    direction: str  # "LEFT" or "RIGHT"


@dataclass(frozen=True)
class MerkleProof:
    """
    Complete Merkle inclusion proof for a transaction within a block.
    """
    tx_id: bytes
    tx_index: int
    merkle_root: bytes
    steps: Tuple[MerkleProofStep, ...]


# ============================================================================
# Abstract Cross-Worklet Interfaces
# ============================================================================

class CanonicalSerializable(ABC):
    """
    Contract for every domain object (TxInput, TxOutput, Transaction, Block)
    requiring deterministic byte-buffer serialization across Worklets 1, 2, and 3.
    """

    @abstractmethod
    def to_bytes(self) -> bytes:
        """Serialize the object into its canonical big-endian byte representation."""

    @classmethod
    @abstractmethod
    def from_bytes(cls, data: bytes) -> "CanonicalSerializable":
        """Deserialize an instance from its canonical byte representation."""


class HashInterface(ABC):
    """
    Worklet 2.4 Contract: Bit-level cryptographic hash interface used across
    Worklet 1 (transaction hashing & address derivation), Worklet 2 (Merkle trees
    & Proof-of-Work), and Worklet 3 (full-chain & persistence validation).
    """

    @property
    @abstractmethod
    def digest_size(self) -> int:
        """Return digest size in bytes (32 bytes / 256 bits)."""

    @abstractmethod
    def hash_bytes(self, data: bytes) -> bytes:
        """Compute the 32-byte raw digest of `data`."""

    @abstractmethod
    def hash_hex(self, data: bytes) -> str:
        """Compute the 64-character lowercase hexadecimal digest of `data`."""

    @abstractmethod
    def analyze_avalanche(self, original: bytes, modified: bytes) -> AvalancheReport:
        """
        Compare the bit-level changes between two inputs and their resulting digests
        to demonstrate the avalanche effect and tamper-evidence.
        """


class AsymmetricCryptoInterface(ABC):
    """
    Worklet 1.2 & 1.4 Contract: Public/private key generation, signing, and verification.
    """

    @abstractmethod
    def generate_keypair(self, bit_length: int) -> Tuple[bytes, bytes]:
        """Generate and return a canonically serialized `(public_key_bytes, private_key_bytes)` pair."""

    @abstractmethod
    def sign(self, private_key_bytes: bytes, message_bytes: bytes) -> bytes:
        """Sign canonical `message_bytes` using `private_key_bytes` and return signature bytes."""

    @abstractmethod
    def verify(self, public_key_bytes: bytes, message_bytes: bytes, signature_bytes: bytes) -> bool:
        """Verify `signature_bytes` over `message_bytes` using `public_key_bytes`."""


class LedgerQueryInterface(ABC):
    """
    Worklet 3.3 & Client-Server Contract: Read/write interface exposed by the Ledger
    to separated Wallet clients. Private keys never cross this interface.
    """

    @abstractmethod
    def get_balance(self, address: bytes) -> int:
        """Return the spendable integer balance for `address` by scanning unspent outputs."""

    @abstractmethod
    def get_utxos_for_address(self, address: bytes) -> List[Dict[str, Any]]:
        """Return all unspent transaction outputs locked to `address`."""

    @abstractmethod
    def submit_transaction(self, tx_bytes: bytes) -> bytes:
        """Validate and accept a canonically serialized signed transaction; return `tx_id`."""

    @abstractmethod
    def get_merkle_proof(self, block_index: int, tx_id: bytes) -> Optional[MerkleProof]:
        """Produce a Merkle inclusion proof for `tx_id` in block `block_index`."""
