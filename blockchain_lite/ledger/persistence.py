"""
Blockchain Disk Persistence, Reload Re-Validation & On-Disk Tamper Detection (Worklet 3.4).

Satisfies:
- Worklet 3.4: "Persist the chain and reload it, re-validating; add integrity
  checks for on-disk tampering."
- Pitfall 5: "Persistence that reloads the chain without re-validating it, so
  on-disk tampering slips through."
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional, Sequence, Tuple, Union

from blockchain_lite.crypto.asymmetric import default_crypto_engine
from blockchain_lite.crypto.hashing import default_hasher
from blockchain_lite.interfaces import (
    PROTOCOL_MAGIC,
    PROTOCOL_VERSION,
    AsymmetricCryptoInterface,
    HashInterface,
    SerializationError,
    TamperDetectedError,
    ValidationError,
)
from blockchain_lite.ledger.chain import BlockchainLedger
from blockchain_lite.ledger.consensus import ConsensusParams
from blockchain_lite.ledger.utxo import UTXOSet
from blockchain_lite.ledger.validator import FullChainValidator
from blockchain_lite.models.block import Block
from blockchain_lite.serialization import ByteBuffer


class ChainPersistence:
    """
    Binary Persistence Engine with Multi-Layer On-Disk Tamper Detection & Atomic Writes.

    On-Disk Wire Format:
    `[Magic: 4B ("BCLT")][Version: 1B (1)][Difficulty: 4B][BlockReward: 8B][BlockCount: 4B]`
    `{ [BlockByteLen: 4B][CanonicalBlockBytes: var] }*`
    `[FileIntegritySeal: 32B (SHA-256 over all preceding bytes)]`

    Trust Model & Defense-in-Depth Upon Reload (`Pitfall 5`):
    1. **Layer 1 (Envelope Checksum Seal):** Verifies the 4-byte `BCLT` magic header,
       protocol version, exact byte boundaries, and the 32-byte trailing SHA-256
       `FileIntegritySeal`. Note: Because `FileIntegritySeal` is an unkeyed hash stored
       inside the file itself, it detects accidental corruption or unsealed byte edits,
       but cannot by itself stop an attacker who rewrites the file and recomputes the seal.
    2. **Layer 2 (Mandatory Full-Chain Genesis Re-Validation):** Even if an attacker
       modifies a transaction/block on disk AND recomputes the trailing file seal,
       `load_ledger()` runs `FullChainValidator.validate_chain_or_raise()` from Genesis
       before trusting any state. This catches any forged signature, altered output,
       broken Merkle root, invalid PoW nonce, or broken `previous_hash` link.
    3. **Layer 3 (Pinned Trusted Genesis Anchor — `F-001`):** When `expected_genesis_hash`
       (held outside the mutable ledger file) is supplied to `load_ledger()`, the validator
       also verifies `blocks[0].block_hash == expected_genesis_hash`, preventing an attacker
       from replacing the entire `.bclt` file with a newly mined chain starting from a
       fabricated Genesis block.
    """

    def __init__(
        self,
        crypto_engine: AsymmetricCryptoInterface = default_crypto_engine,
        hasher: HashInterface = default_hasher,
        params: Optional[ConsensusParams] = None,
    ) -> None:
        self._crypto_engine = crypto_engine
        self._hasher = hasher
        # Protocol rules come from the caller (or defaults), never from the file header.
        self._params = params or ConsensusParams()

    def serialize_chain(
        self,
        blocks: Sequence[Block],
        difficulty: int = 8,
        block_reward: int = 50,
    ) -> bytes:
        """Serialize a validated sequence of blocks into a sealed binary image."""
        if not blocks:
            raise ValidationError("Cannot persist an empty blockchain")

        payload_buf = ByteBuffer()
        payload_buf.write_fixed_bytes(PROTOCOL_MAGIC, 4)
        payload_buf.write_uint8(PROTOCOL_VERSION)
        payload_buf.write_uint32(difficulty)
        payload_buf.write_uint64(block_reward)
        payload_buf.write_uint32(len(blocks))

        for block in blocks:
            payload_buf.write_var_bytes(block.to_bytes())

        payload_bytes = payload_buf.to_bytes()
        integrity_seal = self._hasher.hash_bytes(payload_bytes)

        final_buf = ByteBuffer(payload_bytes)
        final_buf.write_hash32(integrity_seal)
        return final_buf.to_bytes()

    def deserialize_and_validate_bytes(
        self,
        raw_file_bytes: bytes,
        verify_envelope_seal: bool = True,
        expected_genesis_hash: Optional[bytes] = None,
        params: Optional[ConsensusParams] = None,
    ) -> Tuple[List[Block], UTXOSet, int, int]:
        """
        Deserialize `raw_file_bytes`, verify the outer SHA-256 envelope seal,
        and ALWAYS execute full Genesis-to-tip cryptographic chain re-validation
        under `params` (default: this engine's protocol params). A header whose
        difficulty / block_reward disagrees with those params is rejected.
        Returns `(blocks, utxo_set, difficulty, block_reward)`.
        """
        params = params or self._params
        if len(raw_file_bytes) < (4 + 1 + 4 + 8 + 4 + 32):
            raise TamperDetectedError(
                f"Persisted chain file is truncated ({len(raw_file_bytes)} bytes)"
            )

        payload_bytes = raw_file_bytes[:-32]
        stored_seal = raw_file_bytes[-32:]
        computed_seal = self._hasher.hash_bytes(payload_bytes)

        if verify_envelope_seal and (stored_seal != computed_seal):
            raise TamperDetectedError(
                "On-disk tampering detected: file SHA-256 integrity seal mismatch "
                f"(stored={stored_seal.hex()[:16]}..., computed={computed_seal.hex()[:16]}...)"
            )

        try:
            reader = ByteBuffer(payload_bytes)
            magic = reader.read_fixed_bytes(4)
            if magic != PROTOCOL_MAGIC:
                raise TamperDetectedError(
                    f"Invalid file magic header: expected {PROTOCOL_MAGIC!r}, got {magic!r}"
                )
            version = reader.read_uint8()
            if version != PROTOCOL_VERSION:
                raise ValidationError(f"Unsupported protocol version: {version}")

            difficulty = reader.read_uint32()
            block_reward = reader.read_uint64()
            block_count = reader.read_uint32()
            if block_count == 0 or block_count > 1_000_000:
                raise TamperDetectedError(f"Invalid persisted block count: {block_count}")

            blocks: List[Block] = []
            for _ in range(block_count):
                block_bytes = reader.read_var_bytes(max_length=50 * 1024 * 1024)
                blocks.append(Block.from_bytes(block_bytes))

            reader.assert_exhausted()
        except SerializationError as exc:
            raise TamperDetectedError(
                f"On-disk tampering / corruption detected during binary deserialization: {exc}"
            ) from exc

        # The header is untrusted: it must agree with the protocol, never redefine it (D2).
        if difficulty != params.initial_difficulty or block_reward != params.block_reward:
            raise TamperDetectedError(
                f"Persisted header (difficulty={difficulty}, block_reward={block_reward}) "
                f"disagrees with protocol parameters (difficulty={params.initial_difficulty}, "
                f"block_reward={params.block_reward})"
            )

        # MANDATORY FULL RE-VALIDATION FROM GENESIS (Worklet 3.4 & Pitfall 5)
        validator = FullChainValidator(
            crypto_engine=self._crypto_engine,
            hasher=self._hasher,
            expected_genesis_hash=expected_genesis_hash,
            params=params,
        )
        utxo_set, _ = validator.validate_chain_or_raise(
            blocks, expected_genesis_hash=expected_genesis_hash
        )
        return blocks, utxo_set, difficulty, block_reward

    def save_ledger(self, ledger: BlockchainLedger, file_path: Union[str, Path]) -> Path:
        """
        Atomically persist `ledger` to `file_path` using a temporary sibling file
        and `os.replace()` (`F-005`), ensuring an interrupted write never corrupts
        a previously saved valid ledger file.
        """
        target = Path(file_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        raw = self.serialize_chain(
            blocks=ledger.blocks,
            difficulty=ledger.difficulty,
            block_reward=ledger.block_reward,
        )
        tmp_path = target.with_suffix(target.suffix + ".tmp")
        try:
            with open(tmp_path, "wb") as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, target)
        except Exception:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
            raise
        return target

    def load_ledger(
        self,
        file_path: Union[str, Path],
        verify_envelope_seal: bool = True,
        expected_genesis_hash: Optional[bytes] = None,
        params: Optional[ConsensusParams] = None,
    ) -> BlockchainLedger:
        """
        Load a `BlockchainLedger` from `file_path` and re-validate every block,
        Merkle root, PoW hash, and transaction signature from Genesis before returning.
        """
        params = params or self._params
        target = Path(file_path)
        if not target.is_file():
            raise ValidationError(f"Ledger persistence file not found: {target}")

        raw = target.read_bytes()
        blocks, _, _, _ = self.deserialize_and_validate_bytes(
            raw,
            verify_envelope_seal=verify_envelope_seal,
            expected_genesis_hash=expected_genesis_hash,
            params=params,
        )
        ledger = BlockchainLedger(
            difficulty=params.initial_difficulty,
            block_reward=params.block_reward,
            crypto_engine=self._crypto_engine,
            hasher=self._hasher,
            retarget_interval=params.retarget_interval,
            target_block_time_seconds=params.target_block_time_seconds,
            min_difficulty=params.min_difficulty,
            max_difficulty=params.max_difficulty,
        )
        ledger.load_verified_chain(blocks)
        return ledger
