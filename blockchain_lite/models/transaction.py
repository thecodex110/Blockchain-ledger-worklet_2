"""
Transaction, TxInput, and TxOutput Models & Intra-Block Double-Spend / Tamper Validator
(Worklet 1.3, 1.4 & 1.5).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Optional, Sequence, Set, Tuple

from blockchain_lite.crypto.asymmetric import RSAPublicKey, default_crypto_engine
from blockchain_lite.crypto.hashing import default_hasher
from blockchain_lite.interfaces import (
    HASH_DIGEST_SIZE,
    MAX_TOKEN_SUPPLY,
    MAX_UINT32,
    MAX_UINT64,
    TX_TYPE_COINBASE,
    TX_TYPE_TRANSFER,
    AsymmetricCryptoInterface,
    CanonicalSerializable,
    CryptoError,
    DoubleSpendError,
    HashInterface,
    SerializationError,
    TamperDetectedError,
    ValidationError,
)
from blockchain_lite.serialization import ByteBuffer


@dataclass(frozen=True)
class TxInput(CanonicalSerializable):
    """References an existing UTXO by `(prev_tx_id, output_index)` with owner pubkey & signature."""
    prev_tx_id: bytes
    output_index: int
    sender_pubkey: bytes
    signature: bytes = b""

    def __post_init__(self) -> None:
        if not isinstance(self.prev_tx_id, bytes) or len(self.prev_tx_id) != HASH_DIGEST_SIZE:
            raise ValidationError(
                f"TxInput.prev_tx_id must be exactly {HASH_DIGEST_SIZE} bytes"
            )
        if isinstance(self.output_index, bool) or not isinstance(self.output_index, int):
            raise ValidationError("TxInput.output_index must be an integer")
        if self.output_index < 0 or self.output_index > MAX_UINT32:
            raise ValidationError(f"TxInput.output_index out of uint32 range: {self.output_index}")
        if not isinstance(self.sender_pubkey, bytes) or len(self.sender_pubkey) == 0:
            raise ValidationError("TxInput.sender_pubkey must be non-empty bytes")
        if not isinstance(self.signature, bytes):
            raise ValidationError("TxInput.signature must be bytes")

    @property
    def outpoint_key(self) -> Tuple[bytes, int]:
        return (self.prev_tx_id, self.output_index)

    @property
    def outpoint_str(self) -> str:
        return f"{self.prev_tx_id.hex()}:{self.output_index}"

    def sender_address(self, hasher: HashInterface = default_hasher) -> bytes:
        return hasher.hash_bytes(self.sender_pubkey)

    def write_unsigned_to_buffer(self, buf: ByteBuffer) -> None:
        buf.write_hash32(self.prev_tx_id)
        buf.write_uint32(self.output_index)
        buf.write_var_bytes(self.sender_pubkey)

    def write_to_buffer(self, buf: ByteBuffer) -> None:
        self.write_unsigned_to_buffer(buf)
        buf.write_var_bytes(self.signature)

    def to_bytes(self) -> bytes:
        buf = ByteBuffer()
        self.write_to_buffer(buf)
        return buf.to_bytes()

    @classmethod
    def read_from_buffer(cls, reader: ByteBuffer) -> "TxInput":
        prev_tx_id = reader.read_hash32()
        output_index = reader.read_uint32()
        sender_pubkey = reader.read_var_bytes(max_length=8192)
        signature = reader.read_var_bytes(max_length=8192)
        return cls(
            prev_tx_id=prev_tx_id,
            output_index=output_index,
            sender_pubkey=sender_pubkey,
            signature=signature,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "TxInput":
        reader = ByteBuffer(data)
        tx_in = cls.read_from_buffer(reader)
        reader.assert_exhausted()
        return tx_in


@dataclass(frozen=True)
class TxOutput(CanonicalSerializable):
    """Represents a spendable output locking `amount` integer units to `recipient_address`."""
    amount: int
    recipient_address: bytes

    def __post_init__(self) -> None:
        if isinstance(self.amount, bool) or not isinstance(self.amount, int):
            raise ValidationError(
                f"TxOutput.amount must be an integer (no floats/booleans), got {type(self.amount).__name__}"
            )
        if self.amount <= 0 or self.amount > MAX_TOKEN_SUPPLY:
            raise ValidationError(
                f"TxOutput.amount must be in [1, {MAX_TOKEN_SUPPLY}], got {self.amount}"
            )
        if (
            not isinstance(self.recipient_address, bytes)
            or len(self.recipient_address) != HASH_DIGEST_SIZE
        ):
            raise ValidationError(
                f"TxOutput.recipient_address must be exactly {HASH_DIGEST_SIZE} bytes"
            )

    def write_to_buffer(self, buf: ByteBuffer) -> None:
        buf.write_uint64(self.amount)
        buf.write_hash32(self.recipient_address)

    def to_bytes(self) -> bytes:
        buf = ByteBuffer()
        self.write_to_buffer(buf)
        return buf.to_bytes()

    @classmethod
    def read_from_buffer(cls, reader: ByteBuffer) -> "TxOutput":
        amount = reader.read_uint64()
        recipient_address = reader.read_hash32()
        return cls(amount=amount, recipient_address=recipient_address)

    @classmethod
    def from_bytes(cls, data: bytes) -> "TxOutput":
        reader = ByteBuffer(data)
        tx_out = cls.read_from_buffer(reader)
        reader.assert_exhausted()
        return tx_out


@dataclass(frozen=True)
class Transaction(CanonicalSerializable):
    """A cryptographically signed UTXO transaction."""
    tx_type: int
    timestamp: int
    inputs: Tuple[TxInput, ...]
    outputs: Tuple[TxOutput, ...]

    def __post_init__(self) -> None:
        if self.tx_type not in (TX_TYPE_COINBASE, TX_TYPE_TRANSFER):
            raise ValidationError(f"Invalid tx_type: {self.tx_type}")
        if isinstance(self.timestamp, bool) or not isinstance(self.timestamp, int):
            raise ValidationError("Transaction.timestamp must be an integer")
        if self.timestamp < 0 or self.timestamp > MAX_UINT64:
            raise ValidationError(f"Transaction.timestamp out of uint64 range: {self.timestamp}")
        if not isinstance(self.inputs, tuple):
            object.__setattr__(self, "inputs", tuple(self.inputs))
        if not isinstance(self.outputs, tuple):
            object.__setattr__(self, "outputs", tuple(self.outputs))

        if len(self.outputs) == 0:
            raise ValidationError("Transaction must have at least one output")

        if self.tx_type == TX_TYPE_COINBASE:
            if len(self.inputs) != 0:
                raise ValidationError("Coinbase transaction must not have any inputs")
        else:
            if len(self.inputs) == 0:
                raise ValidationError("Transfer transaction must have at least one input")

        total_out = 0
        for out in self.outputs:
            if not isinstance(out, TxOutput):
                raise ValidationError("All outputs must be TxOutput instances")
            total_out += out.amount
            if total_out > MAX_TOKEN_SUPPLY:
                raise ValidationError("Total transaction output exceeds MAX_TOKEN_SUPPLY")

        for tx_in in self.inputs:
            if not isinstance(tx_in, TxInput):
                raise ValidationError("All inputs must be TxInput instances")

    @classmethod
    def create_coinbase(
        cls,
        recipient_address: bytes,
        amount: int,
        timestamp: int = 0,
    ) -> "Transaction":
        return cls(
            tx_type=TX_TYPE_COINBASE,
            timestamp=timestamp,
            inputs=(),
            outputs=(TxOutput(amount=amount, recipient_address=recipient_address),),
        )

    @property
    def total_output_amount(self) -> int:
        return sum(out.amount for out in self.outputs)

    def signing_preimage_bytes(self) -> bytes:
        buf = ByteBuffer()
        buf.write_uint8(self.tx_type)
        buf.write_uint64(self.timestamp)
        buf.write_uint32(len(self.inputs))
        for tx_in in self.inputs:
            tx_in.write_unsigned_to_buffer(buf)
        buf.write_uint32(len(self.outputs))
        for tx_out in self.outputs:
            tx_out.write_to_buffer(buf)
        return buf.to_bytes()

    def write_to_buffer(self, buf: ByteBuffer) -> None:
        buf.write_uint8(self.tx_type)
        buf.write_uint64(self.timestamp)
        buf.write_uint32(len(self.inputs))
        for tx_in in self.inputs:
            tx_in.write_to_buffer(buf)
        buf.write_uint32(len(self.outputs))
        for tx_out in self.outputs:
            tx_out.write_to_buffer(buf)

    def to_bytes(self) -> bytes:
        buf = ByteBuffer()
        self.write_to_buffer(buf)
        return buf.to_bytes()

    @classmethod
    def read_from_buffer(cls, reader: ByteBuffer) -> "Transaction":
        tx_type = reader.read_uint8()
        timestamp = reader.read_uint64()
        in_count = reader.read_uint32()
        if in_count > 10_000:
            raise SerializationError(f"Unreasonable input count: {in_count}")
        inputs = tuple(TxInput.read_from_buffer(reader) for _ in range(in_count))

        out_count = reader.read_uint32()
        if out_count > 10_000:
            raise SerializationError(f"Unreasonable output count: {out_count}")
        outputs = tuple(TxOutput.read_from_buffer(reader) for _ in range(out_count))

        return cls(
            tx_type=tx_type,
            timestamp=timestamp,
            inputs=inputs,
            outputs=outputs,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "Transaction":
        try:
            reader = ByteBuffer(data)
            tx = cls.read_from_buffer(reader)
            reader.assert_exhausted()
            return tx
        except ValidationError as exc:
            raise SerializationError(f"Invalid transaction in canonical bytes: {exc}") from exc

    def compute_tx_id(self, hasher: HashInterface = default_hasher) -> bytes:
        return hasher.hash_bytes(self.to_bytes())

    @property
    def tx_id(self) -> bytes:
        return self.compute_tx_id(default_hasher)

    @property
    def tx_id_hex(self) -> str:
        return self.tx_id.hex()

    def verify_signatures(
        self,
        crypto_engine: AsymmetricCryptoInterface = default_crypto_engine,
    ) -> bool:
        if self.tx_type == TX_TYPE_COINBASE:
            return len(self.inputs) == 0

        preimage = self.signing_preimage_bytes()
        for tx_in in self.inputs:
            if not tx_in.signature:
                return False
            try:
                RSAPublicKey.from_bytes(tx_in.sender_pubkey)
            except CryptoError:
                return False
            if not crypto_engine.verify(tx_in.sender_pubkey, preimage, tx_in.signature):
                return False
        return True


def validate_transaction_integrity(
    tx: Transaction,
    crypto_engine: AsymmetricCryptoInterface = default_crypto_engine,
) -> None:
    seen_outpoints: Set[Tuple[bytes, int]] = set()
    for tx_in in tx.inputs:
        key = tx_in.outpoint_key
        if key in seen_outpoints:
            raise DoubleSpendError(
                f"Intra-transaction double-spend detected on UTXO {tx_in.outpoint_str}"
            )
        seen_outpoints.add(key)

    if not tx.verify_signatures(crypto_engine=crypto_engine):
        raise TamperDetectedError(
            f"Cryptographic signature verification failed for transaction {tx.tx_id_hex[:16]}... "
            "(transaction payload or signature was tampered with)"
        )


def validate_block_transactions_no_double_spend(
    transactions: Sequence[Transaction],
    available_utxos: Optional[Mapping[Tuple[bytes, int], TxOutput]] = None,
    crypto_engine: AsymmetricCryptoInterface = default_crypto_engine,
    hasher: HashInterface = default_hasher,
) -> None:
    if not transactions:
        raise ValidationError("Block must contain at least one transaction")

    seen_block_outpoints: Set[Tuple[bytes, int]] = set()

    for idx, tx in enumerate(transactions):
        if tx.tx_type == TX_TYPE_COINBASE and idx != 0:
            raise ValidationError(
                f"Coinbase transaction is only permitted at index 0, found at index {idx}"
            )

        validate_transaction_integrity(tx, crypto_engine=crypto_engine)

        input_sum = 0
        for tx_in in tx.inputs:
            outpoint = tx_in.outpoint_key
            if outpoint in seen_block_outpoints:
                raise DoubleSpendError(
                    f"Intra-block double-spend detected at tx index {idx}: "
                    f"UTXO {tx_in.outpoint_str} was already spent earlier in the same block"
                )
            seen_block_outpoints.add(outpoint)

            if available_utxos is not None:
                if outpoint not in available_utxos:
                    raise DoubleSpendError(
                        f"Transaction {tx.tx_id_hex[:16]}... references missing or already-spent "
                        f"UTXO {tx_in.outpoint_str}"
                    )
                utxo = available_utxos[outpoint]
                derived_addr = tx_in.sender_address(hasher=hasher)
                if derived_addr != utxo.recipient_address:
                    raise TamperDetectedError(
                        f"Unauthorized UTXO spend in tx {tx.tx_id_hex[:16]}...: "
                        f"sender pubkey hash {derived_addr.hex()[:16]} does not match "
                        f"UTXO owner address {utxo.recipient_address.hex()[:16]}"
                    )
                input_sum += utxo.amount

        if tx.tx_type == TX_TYPE_TRANSFER and available_utxos is not None:
            output_sum = tx.total_output_amount
            if input_sum < output_sum:
                raise ValidationError(
                    f"Insufficient input value in tx {tx.tx_id_hex[:16]}...: "
                    f"inputs={input_sum} < outputs={output_sum}"
                )
