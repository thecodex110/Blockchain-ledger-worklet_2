"""
UTXO Hash-Map Engine & Balance / Ledger Query Support (Worklet 3.3).

Satisfies:
- Data structures: "Hash map for balances / unspent outputs"
- Worklet 3.3: "Compute balances by scanning unspent outputs; build a ledger query interface."
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Mapping, Optional, Tuple

from blockchain_lite.crypto.asymmetric import default_crypto_engine
from blockchain_lite.crypto.hashing import default_hasher
from blockchain_lite.interfaces import (
    TX_TYPE_COINBASE,
    TX_TYPE_TRANSFER,
    AsymmetricCryptoInterface,
    DoubleSpendError,
    HashInterface,
    TamperDetectedError,
    ValidationError,
)
from blockchain_lite.models.block import Block
from blockchain_lite.models.transaction import (
    Transaction,
    TxOutput,
    validate_transaction_integrity,
)
from blockchain_lite.wallet.wallet import SpendableUTXO


@dataclass(frozen=True)
class UTXOEntry:
    """
    Authoritative record of a single Unspent Transaction Output in the Ledger's UTXO hash map.
    """
    tx_id: bytes
    output_index: int
    amount: int
    recipient_address: bytes
    block_index: int
    is_coinbase: bool

    @property
    def outpoint_key(self) -> Tuple[bytes, int]:
        return (self.tx_id, self.output_index)

    @property
    def outpoint_str(self) -> str:
        return f"{self.tx_id.hex()}:{self.output_index}"

    def to_tx_output(self) -> TxOutput:
        return TxOutput(amount=self.amount, recipient_address=self.recipient_address)

    def to_spendable_utxo(self) -> SpendableUTXO:
        return SpendableUTXO(
            tx_id=self.tx_id,
            output_index=self.output_index,
            amount=self.amount,
            recipient_address=self.recipient_address,
        )


class UTXOSet:
    """
    Hash-map backed Unspent Transaction Output (UTXO) state engine.
    Maps `(tx_id: bytes32, output_index: int) -> UTXOEntry`.
    """

    def __init__(
        self,
        initial_entries: Optional[Mapping[Tuple[bytes, int], UTXOEntry]] = None,
    ) -> None:
        self._map: Dict[Tuple[bytes, int], UTXOEntry] = (
            dict(initial_entries) if initial_entries else {}
        )

    def clone(self) -> "UTXOSet":
        """Return a shallow copy of the UTXO hash map for atomic validation staging."""
        return UTXOSet(self._map)

    def __len__(self) -> int:
        return len(self._map)

    def __contains__(self, outpoint: Tuple[bytes, int]) -> bool:
        return outpoint in self._map

    def get(self, outpoint: Tuple[bytes, int]) -> Optional[UTXOEntry]:
        return self._map.get(outpoint)

    @property
    def entries(self) -> Mapping[Tuple[bytes, int], UTXOEntry]:
        return self._map

    def to_tx_output_map(self) -> Dict[Tuple[bytes, int], TxOutput]:
        return {k: v.to_tx_output() for k, v in self._map.items()}

    # ------------------------------------------------------------------------
    # Balance & UTXO Scanning Queries (Worklet 3.3)
    # ------------------------------------------------------------------------

    def compute_balance(self, address: bytes) -> int:
        """
        Worklet 3.3: Compute a wallet's balance by scanning unspent outputs in the hash map.
        """
        total = 0
        for entry in self._map.values():
            if entry.recipient_address == address:
                total += entry.amount
        return total

    def get_utxos_for_address(self, address: bytes) -> List[UTXOEntry]:
        """Return all `UTXOEntry` objects locked to `address` sorted deterministically."""
        matched = [
            entry for entry in self._map.values() if entry.recipient_address == address
        ]
        matched.sort(key=lambda e: (e.block_index, e.tx_id, e.output_index))
        return matched

    def get_spendable_utxos(self, address: bytes) -> List[SpendableUTXO]:
        """Return client-ready `SpendableUTXO` records for `address`."""
        return [e.to_spendable_utxo() for e in self.get_utxos_for_address(address)]

    @property
    def total_supply(self) -> int:
        """Sum of all unspent outputs currently in existence across the ledger."""
        return sum(entry.amount for entry in self._map.values())

    # ------------------------------------------------------------------------
    # Atomic State Transitions
    # ------------------------------------------------------------------------

    def apply_transaction(
        self,
        tx: Transaction,
        block_index: int,
        crypto_engine: AsymmetricCryptoInterface = default_crypto_engine,
        hasher: HashInterface = default_hasher,
    ) -> int:
        """
        Validate and apply a single transaction `tx` to this `UTXOSet`.
        Returns the integer transaction fee (`input_sum - output_sum` for transfers, `0` for coinbase).
        Raises `TamperDetectedError`, `DoubleSpendError`, or `ValidationError` on any violation.
        """
        validate_transaction_integrity(tx, crypto_engine=crypto_engine)
        tx_id = tx.compute_tx_id(hasher=hasher)

        fee = 0
        if tx.tx_type == TX_TYPE_TRANSFER:
            input_sum = 0
            # Verify all inputs exist and belong to their respective signers before mutating
            for tx_in in tx.inputs:
                outpoint = tx_in.outpoint_key
                utxo = self._map.get(outpoint)
                if utxo is None:
                    raise DoubleSpendError(
                        f"Transaction {tx_id.hex()[:16]}... spends missing or already-spent "
                        f"UTXO {tx_in.outpoint_str}"
                    )
                signer_addr = tx_in.sender_address(hasher=hasher)
                if signer_addr != utxo.recipient_address:
                    raise TamperDetectedError(
                        f"Transaction {tx_id.hex()[:16]}... input signer address "
                        f"{signer_addr.hex()[:16]}... does not own UTXO {tx_in.outpoint_str}"
                    )
                input_sum += utxo.amount

            output_sum = tx.total_output_amount
            if input_sum < output_sum:
                raise ValidationError(
                    f"Transaction {tx_id.hex()[:16]}... output sum ({output_sum}) "
                    f"exceeds input sum ({input_sum})"
                )
            fee = input_sum - output_sum

            # Remove spent inputs
            for tx_in in tx.inputs:
                del self._map[tx_in.outpoint_key]

        # Add newly created outputs
        is_coinbase = tx.tx_type == TX_TYPE_COINBASE
        for out_idx, tx_out in enumerate(tx.outputs):
            new_outpoint = (tx_id, out_idx)
            if new_outpoint in self._map:
                raise DoubleSpendError(
                    f"Duplicate transaction output collision on {tx_id.hex()[:16]}:{out_idx}"
                )
            self._map[new_outpoint] = UTXOEntry(
                tx_id=tx_id,
                output_index=out_idx,
                amount=tx_out.amount,
                recipient_address=tx_out.recipient_address,
                block_index=block_index,
                is_coinbase=is_coinbase,
            )

        return fee

    def apply_block(
        self,
        block: Block,
        max_block_reward: Optional[int] = None,
        crypto_engine: AsymmetricCryptoInterface = default_crypto_engine,
        hasher: HashInterface = default_hasher,
    ) -> None:
        """
        Atomically validate and apply all transactions in `block` against a staged copy
        of the UTXO map, committing changes only if every transaction succeeds.
        """
        staged = self.clone()
        total_fees = 0
        coinbase_tx: Optional[Transaction] = None

        for idx, tx in enumerate(block.transactions):
            if tx.tx_type == TX_TYPE_COINBASE:
                if idx != 0:
                    raise ValidationError(
                        f"Block #{block.index} has a coinbase transaction at non-zero index {idx}"
                    )
                coinbase_tx = tx
                staged.apply_transaction(
                    tx,
                    block_index=block.index,
                    crypto_engine=crypto_engine,
                    hasher=hasher,
                )
            else:
                fee = staged.apply_transaction(
                    tx,
                    block_index=block.index,
                    crypto_engine=crypto_engine,
                    hasher=hasher,
                )
                total_fees += fee

        # Enforce coinbase reward cap on non-genesis blocks when max_block_reward is configured
        if (
            block.index > 0
            and coinbase_tx is not None
            and max_block_reward is not None
        ):
            allowed_coinbase = max_block_reward + total_fees
            if coinbase_tx.total_output_amount > allowed_coinbase:
                raise ValidationError(
                    f"Block #{block.index} coinbase output ({coinbase_tx.total_output_amount}) "
                    f"exceeds allowed reward + fees ({allowed_coinbase})"
                )

        # Atomic swap
        self._map = staged._map
