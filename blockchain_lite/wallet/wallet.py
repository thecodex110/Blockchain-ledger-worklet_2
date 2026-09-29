"""
Digital Wallet Client Model (Worklet 1.3 & 1.4).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import List, Optional, Sequence

from blockchain_lite.crypto.asymmetric import (
    DEFAULT_RSA_MODULUS_BITS,
    RSACryptoEngine,
    RSAPrivateKey,
    RSAPublicKey,
    default_crypto_engine,
)
from blockchain_lite.crypto.hashing import default_hasher
from blockchain_lite.interfaces import (
    TX_TYPE_TRANSFER,
    AsymmetricCryptoInterface,
    CryptoError,
    HashInterface,
    ValidationError,
)
from blockchain_lite.models.transaction import Transaction, TxInput, TxOutput


@dataclass(frozen=True)
class SpendableUTXO:
    """Client-side view of an Unspent Transaction Output owned by a Wallet."""
    tx_id: bytes
    output_index: int
    amount: int
    recipient_address: bytes


class Wallet:
    """Public/Private-Key Digital Wallet (Client Layer)."""

    def __init__(
        self,
        public_key: RSAPublicKey,
        private_key: Optional[RSAPrivateKey] = None,
        label: str = "wallet",
        crypto_engine: AsymmetricCryptoInterface = default_crypto_engine,
        hasher: HashInterface = default_hasher,
    ) -> None:
        if private_key is not None and private_key.public_key != public_key:
            raise CryptoError("Private key does not match the supplied public key")
        self._public_key = public_key
        self._private_key = private_key
        self._label = label
        self._crypto_engine = crypto_engine
        self._hasher = hasher
        self._public_key_bytes = public_key.to_bytes()
        self._address = public_key.derive_address(hasher=hasher)

    @classmethod
    def generate(
        cls,
        label: str = "wallet",
        bit_length: int = DEFAULT_RSA_MODULUS_BITS,
        crypto_engine: RSACryptoEngine = default_crypto_engine,
        hasher: HashInterface = default_hasher,
    ) -> "Wallet":
        pub, priv = crypto_engine.generate_keypair_objects(bit_length=bit_length)
        return cls(
            public_key=pub,
            private_key=priv,
            label=label,
            crypto_engine=crypto_engine,
            hasher=hasher,
        )

    @classmethod
    def from_private_key_bytes(
        cls,
        private_key_bytes: bytes,
        label: str = "wallet",
        crypto_engine: AsymmetricCryptoInterface = default_crypto_engine,
        hasher: HashInterface = default_hasher,
    ) -> "Wallet":
        priv = RSAPrivateKey.from_bytes(private_key_bytes)
        return cls(
            public_key=priv.public_key,
            private_key=priv,
            label=label,
            crypto_engine=crypto_engine,
            hasher=hasher,
        )

    @classmethod
    def watch_only(
        cls,
        public_key_bytes: bytes,
        label: str = "watch-only",
        crypto_engine: AsymmetricCryptoInterface = default_crypto_engine,
        hasher: HashInterface = default_hasher,
    ) -> "Wallet":
        pub = RSAPublicKey.from_bytes(public_key_bytes)
        return cls(
            public_key=pub,
            private_key=None,
            label=label,
            crypto_engine=crypto_engine,
            hasher=hasher,
        )

    @property
    def label(self) -> str:
        return self._label

    @property
    def public_key(self) -> RSAPublicKey:
        return self._public_key

    @property
    def public_key_bytes(self) -> bytes:
        return self._public_key_bytes

    @property
    def address(self) -> bytes:
        return self._address

    @property
    def address_hex(self) -> str:
        return self._address.hex()

    @property
    def can_sign(self) -> bool:
        return self._private_key is not None

    def export_private_key_bytes(self) -> bytes:
        if self._private_key is None:
            raise CryptoError("Watch-only wallet does not hold a private key")
        return self._private_key.to_bytes()

    def sign_bytes(self, message_bytes: bytes) -> bytes:
        if self._private_key is None:
            raise CryptoError("Cannot sign: wallet is watch-only (no private key)")
        return self._crypto_engine.sign(self._private_key.to_bytes(), message_bytes)

    def verify_bytes(self, message_bytes: bytes, signature_bytes: bytes) -> bool:
        return self._crypto_engine.verify(
            self._public_key_bytes, message_bytes, signature_bytes
        )

    def sign_transaction(self, unsigned_tx: Transaction) -> Transaction:
        if self._private_key is None:
            raise CryptoError("Cannot sign transaction: wallet has no private key")

        preimage = unsigned_tx.signing_preimage_bytes()
        priv_bytes = self._private_key.to_bytes()
        sig = self._crypto_engine.sign(priv_bytes, preimage)

        signed_inputs: List[TxInput] = []
        for tx_in in unsigned_tx.inputs:
            if tx_in.sender_pubkey == self._public_key_bytes:
                signed_inputs.append(
                    TxInput(
                        prev_tx_id=tx_in.prev_tx_id,
                        output_index=tx_in.output_index,
                        sender_pubkey=tx_in.sender_pubkey,
                        signature=sig,
                    )
                )
            else:
                signed_inputs.append(tx_in)

        return Transaction(
            tx_type=unsigned_tx.tx_type,
            timestamp=unsigned_tx.timestamp,
            inputs=tuple(signed_inputs),
            outputs=unsigned_tx.outputs,
        )

    def create_signed_transfer(
        self,
        recipient_address: bytes,
        amount: int,
        spendable_utxos: Sequence[SpendableUTXO],
        fee: int = 0,
        timestamp: Optional[int] = None,
    ) -> Transaction:
        if self._private_key is None:
            raise CryptoError("Watch-only wallet cannot create signed transfers")
        if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
            raise ValidationError(f"Transfer amount must be a positive integer, got {amount!r}")
        if isinstance(fee, bool) or not isinstance(fee, int) or fee < 0:
            raise ValidationError(f"Transaction fee must be a non-negative integer, got {fee!r}")

        required_total = amount + fee

        owned_utxos = [
            u for u in spendable_utxos if u.recipient_address == self._address
        ]
        owned_utxos.sort(key=lambda u: (u.amount, u.tx_id, u.output_index))

        selected: List[SpendableUTXO] = []
        accumulated = 0
        for utxo in owned_utxos:
            selected.append(utxo)
            accumulated += utxo.amount
            if accumulated >= required_total:
                break

        if accumulated < required_total:
            raise ValidationError(
                f"Insufficient spendable balance in wallet '{self._label}': "
                f"available={accumulated}, required={required_total} (amount={amount}, fee={fee})"
            )

        unsigned_inputs = tuple(
            TxInput(
                prev_tx_id=u.tx_id,
                output_index=u.output_index,
                sender_pubkey=self._public_key_bytes,
                signature=b"",
            )
            for u in selected
        )

        outputs_list: List[TxOutput] = [
            TxOutput(amount=amount, recipient_address=recipient_address)
        ]
        change = accumulated - required_total
        if change > 0:
            outputs_list.append(
                TxOutput(amount=change, recipient_address=self._address)
            )

        tx_timestamp = int(time.time()) if timestamp is None else timestamp
        unsigned_tx = Transaction(
            tx_type=TX_TYPE_TRANSFER,
            timestamp=tx_timestamp,
            inputs=unsigned_inputs,
            outputs=tuple(outputs_list),
        )
        return self.sign_transaction(unsigned_tx)

    @staticmethod
    def verify_transaction(
        tx: Transaction,
        crypto_engine: AsymmetricCryptoInterface = default_crypto_engine,
    ) -> bool:
        return tx.verify_signatures(crypto_engine=crypto_engine)
