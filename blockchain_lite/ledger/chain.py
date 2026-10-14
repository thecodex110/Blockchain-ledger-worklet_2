"""
Blockchain Ledger State Manager & Most-Work Valid-Chain Fork Resolution (Worklet 3.2 & 3.3).

Satisfies:
- Algorithms: "Longest-valid-chain fork resolution"
- Worklet 3.2: "Resolve forks with a longest-valid-chain rule; show one altered
  transaction invalidates the rest."
- Worklet 3.3: "Compute balances by scanning unspent outputs; build a ledger query interface."
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, replace
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

from blockchain_lite.crypto.asymmetric import default_crypto_engine
from blockchain_lite.crypto.hashing import default_hasher
from blockchain_lite.interfaces import (
    GENESIS_PREV_HASH,
    TX_TYPE_COINBASE,
    AsymmetricCryptoInterface,
    DoubleSpendError,
    HashInterface,
    LedgerQueryInterface,
    MerkleProof,
    ValidationError,
)
from blockchain_lite.ledger.consensus import (
    MAX_FUTURE_DRIFT_SECONDS,
    ConsensusParams,
    check_block_consensus,
    expected_difficulty,
)
from blockchain_lite.ledger.pow import MiningStats, ProofOfWorkMiner, verify_block_pow
from blockchain_lite.ledger.utxo import UTXOSet
from blockchain_lite.ledger.validator import (
    ChainValidationReport,
    FullChainValidator,
    TamperCascadeReport,
)
from blockchain_lite.models.block import Block
from blockchain_lite.models.transaction import (
    Transaction,
    TxOutput,
    validate_block_transactions_no_double_spend,
)
from blockchain_lite.wallet.wallet import SpendableUTXO


@dataclass(frozen=True)
class ForkResolutionOutcome:
    """
    Details the outcome of evaluating competing chain branches under the
    most-cumulative-work valid-chain rule.
    """
    switched_chain: bool
    winning_chain_length: int
    winning_cumulative_work: int
    winning_tip_hash_hex: str
    valid_candidates_count: int
    rejected_candidates_count: int
    rejection_reasons: Tuple[str, ...]


class BlockchainLedger(LedgerQueryInterface):
    """
    Authoritative Blockchain-Lite Ledger Server State.

    Responsibilities:
    - Maintains the active hash-linked list/sequence of `Block` objects from Genesis.
    - Maintains the authoritative `UTXOSet` derived strictly from the active chain.
    - Validates and queues incoming signed transactions in a mempool (preventing
      duplicate or double-spending submissions) under a re-entrant state lock.
    - Mines new PoW blocks over pending transactions.
    - Resolves competing forks by most cumulative schedule-verified work among valid chains (`Worklet 3.2`),
      requiring candidate forks to share the active Genesis block trust anchor (`F-001`).
    - Exposes the read/write `LedgerQueryInterface` for separated Wallet clients (`Worklet 3.3`).
    """

    def __init__(
        self,
        difficulty: int = 8,
        block_reward: int = 50,
        crypto_engine: AsymmetricCryptoInterface = default_crypto_engine,
        hasher: HashInterface = default_hasher,
        retarget_interval: int = 0,
        target_block_time_seconds: float = 10.0,
        min_difficulty: int = 1,
        max_difficulty: int = 24,
        max_mempool_size: int = 5000,
        min_fee: int = 0,
    ) -> None:
        self._lock = threading.RLock()
        self._mining_lock = threading.Lock()  # one miner at a time; never blocks readers
        self._max_mempool_size = max_mempool_size
        self._min_fee = min_fee
        self._health_cache: Optional[Tuple[bytes, ChainValidationReport]] = None
        self._crypto_engine = crypto_engine
        self._hasher = hasher
        self._miner = ProofOfWorkMiner(hasher=hasher)
        self._blocks: List[Block] = []
        self._set_params(ConsensusParams(
            initial_difficulty=difficulty,
            block_reward=block_reward,
            retarget_interval=retarget_interval,
            target_block_time_seconds=target_block_time_seconds,
            min_difficulty=min_difficulty,
            max_difficulty=max_difficulty,
        ))
        self._utxo_set: UTXOSet = UTXOSet()
        self._mempool: Dict[bytes, Transaction] = {}            # tx_id -> tx, insertion-ordered
        self._mempool_spent: Set[Tuple[bytes, int]] = set()     # outpoints claimed by mempool txs
        self._address_history_index: Dict[bytes, List[Dict[str, Any]]] = {}

    # ------------------------------------------------------------------------
    # Genesis & Chain Initialization
    # ------------------------------------------------------------------------

    def create_genesis_block(
        self,
        initial_allocations: Sequence[Tuple[bytes, int]],
        timestamp: int = 1700000000,
    ) -> Block:
        """
        Initialize the chain with a mined Genesis Block (`index = 0`, `previous_hash = 0x00..00`)
        funding the specified `(recipient_address, amount)` pairs.
        """
        with self._lock:
            if self._blocks:
                raise ValidationError("Genesis block has already been initialized")
            if not initial_allocations:
                raise ValidationError("Genesis block requires at least one initial allocation")

            outputs = tuple(
                TxOutput(amount=amt, recipient_address=addr)
                for addr, amt in initial_allocations
            )
            genesis_coinbase = Transaction(
                tx_type=TX_TYPE_COINBASE,
                timestamp=timestamp,
                inputs=(),
                outputs=outputs,
            )

            genesis_block = self._miner.mine_block(
                index=0,
                previous_hash=GENESIS_PREV_HASH,
                transactions=[genesis_coinbase],
                difficulty=self._params.initial_difficulty,
                timestamp=timestamp,
            )
            self.load_verified_chain([genesis_block])
            return genesis_block

    def load_verified_chain(
        self,
        blocks: Sequence[Block],
        expected_genesis_hash: Optional[bytes] = None,
    ) -> ChainValidationReport:
        """
        Validate `blocks` from Genesis to tip and atomically replace the ledger's
        active chain and UTXO set if and only if validation succeeds.
        """
        with self._lock:
            utxo_set, work = self._validator.validate_chain_or_raise(
                blocks, expected_genesis_hash=expected_genesis_hash
            )
            self._blocks = list(blocks)
            self._utxo_set = utxo_set
            self._prune_mempool()
            self._rebuild_history_index()
            return ChainValidationReport(
                is_valid=True,
                block_count=len(self._blocks),
                total_transactions=sum(len(b.transactions) for b in self._blocks),
                cumulative_pow_work=work,
                utxo_set=utxo_set.clone(),
            )

    def _rebuild_history_index(self) -> None:
        """Rebuild the O(1) address transaction history index across all committed blocks."""
        self._address_history_index.clear()
        for block in self._blocks:
            self._index_block_transactions(block)

    def _index_block_transactions(self, block: Block) -> None:
        """Index all transactions in a block for O(1) address history queries."""
        for tx_idx, tx in enumerate(block.transactions):
            tx_id_hex = tx.compute_tx_id(self._hasher).hex()
            is_coinbase = (tx.tx_type == TX_TYPE_COINBASE)
            senders = {tx_in.sender_address(self._hasher) for tx_in in tx.inputs}

            recipient_amounts: Dict[bytes, int] = {}
            for out in tx.outputs:
                recipient_amounts[out.recipient_address] = (
                    recipient_amounts.get(out.recipient_address, 0) + out.amount
                )

            all_addrs = senders | set(recipient_amounts.keys())
            for addr in all_addrs:
                sent_from_addr = (addr in senders)
                received_amount = recipient_amounts.get(addr, 0)
                if sent_from_addr or received_amount > 0:
                    entry = {
                        "block_index": block.index,
                        "tx_index": tx_idx,
                        "tx_id": tx_id_hex,
                        "tx_type": "COINBASE" if is_coinbase else "TRANSFER",
                        # A non-genesis coinbase's timestamp field holds the block height.
                        "timestamp": block.timestamp if is_coinbase else tx.timestamp,
                        "is_sender": sent_from_addr,
                        "received_amount": received_amount,
                        "total_output_amount": tx.total_output_amount,
                    }
                    if addr not in self._address_history_index:
                        self._address_history_index[addr] = []
                    self._address_history_index[addr].append(entry)

    # ------------------------------------------------------------------------
    # Dynamic Difficulty Retargeting
    # ------------------------------------------------------------------------

    @property
    def params(self) -> ConsensusParams:
        return self._params

    @property
    def hasher(self) -> HashInterface:
        return self._hasher

    @property
    def retarget_interval(self) -> int:
        return self._params.retarget_interval

    @property
    def target_block_time_seconds(self) -> float:
        return self._params.target_block_time_seconds

    def _set_params(self, params: ConsensusParams) -> None:
        """Consensus rules apply to the whole chain, so they may only change before Genesis."""
        with self._lock:
            if self._blocks:
                raise ValidationError("Consensus parameters cannot change after Genesis")
            self._params = params
            self._validator = FullChainValidator(
                crypto_engine=self._crypto_engine,
                hasher=self._hasher,
                params=params,
            )

    def enable_dynamic_retargeting(
        self,
        interval: int = 4,
        target_block_time: float = 10.0,
        min_difficulty: int = 1,
        max_difficulty: int = 24,
    ) -> None:
        """Enable difficulty retargeting every `interval` blocks (before Genesis only)."""
        if interval <= 0:
            raise ValidationError("retarget_interval must be positive")
        self._set_params(replace(
            self._params,
            retarget_interval=interval,
            target_block_time_seconds=target_block_time,
            min_difficulty=min_difficulty,
            max_difficulty=max_difficulty,
        ))

    def disable_dynamic_retargeting(self) -> None:
        """Revert to fixed difficulty (before Genesis only)."""
        self._set_params(replace(self._params, retarget_interval=0))

    def calculate_next_difficulty(self) -> int:
        """Pure query: the difficulty consensus requires for the next block."""
        with self._lock:
            return expected_difficulty(self._blocks, self._params)

    # ------------------------------------------------------------------------
    # Properties & Chain Inspection
    # ------------------------------------------------------------------------

    @property
    def blocks(self) -> Tuple[Block, ...]:
        with self._lock:
            return tuple(self._blocks)

    def get_block(self, index: int) -> Block:
        """O(1) block lookup without copying the chain (raises IndexError if absent)."""
        with self._lock:
            if index < 0:
                raise IndexError(index)
            return self._blocks[index]

    @property
    def height(self) -> int:
        """Number of blocks in the active chain (`0` if uninitialized)."""
        with self._lock:
            return len(self._blocks)

    @property
    def genesis_hash(self) -> Optional[bytes]:
        """Return the 32-byte `block_hash` of the active Genesis block, or `None` if empty."""
        with self._lock:
            return self._blocks[0].block_hash if self._blocks else None

    @property
    def tip(self) -> Block:
        with self._lock:
            if not self._blocks:
                raise ValidationError("Blockchain is empty (no Genesis block)")
            return self._blocks[-1]

    @property
    def validator(self) -> FullChainValidator:
        return self._validator

    def add_checkpoint(self, block_index: int, block_hash: bytes) -> None:
        """Register a trusted checkpoint in the ledger's chain validator."""
        with self._lock:
            self._validator.register_checkpoint(block_index, block_hash)

    def trace_tamper_cascade(
        self,
        tampered_block_index: int = 1,
        tampered_tx_index: int = 0,
    ) -> TamperCascadeReport:
        """
        Synthesize a 1-byte tamper in the active chain at (tampered_block_index, tampered_tx_index)
        and trace the resulting cryptographic cascade failure across signatures, Merkle roots,
        PoW nonces, and downstream block links.
        """
        with self._lock:
            if not self._blocks:
                raise ValidationError("Blockchain is empty")
            if tampered_block_index < 0 or tampered_block_index >= len(self._blocks):
                raise ValidationError(f"Invalid block_index {tampered_block_index}")
            target_block = self._blocks[tampered_block_index]
            if tampered_tx_index < 0 or tampered_tx_index >= len(target_block.transactions):
                raise ValidationError(f"Invalid tx_index {tampered_tx_index}")

            target_tx = target_block.transactions[tampered_tx_index]
            mutated_outputs = list(target_tx.outputs)
            if mutated_outputs:
                first_out = mutated_outputs[0]
                mutated_outputs[0] = TxOutput(
                    amount=first_out.amount + 1,
                    recipient_address=first_out.recipient_address,
                )
            mutated_tx = Transaction(
                tx_type=target_tx.tx_type,
                timestamp=target_tx.timestamp,
                inputs=target_tx.inputs,
                outputs=tuple(mutated_outputs),
            )

            mutated_txs = list(target_block.transactions)
            mutated_txs[tampered_tx_index] = mutated_tx

            poisoned_block = Block(
                index=target_block.index,
                previous_hash=target_block.previous_hash,
                merkle_root=target_block.merkle_root,
                timestamp=target_block.timestamp,
                difficulty=target_block.difficulty,
                nonce=target_block.nonce,
                transactions=tuple(mutated_txs),
                block_hash=target_block.block_hash,
            )

            tampered_chain = list(self._blocks)
            tampered_chain[tampered_block_index] = poisoned_block

            return self._validator.trace_tamper_cascade(
                original_chain=self._blocks,
                tampered_chain=tampered_chain,
                block_index=tampered_block_index,
                tx_index=tampered_tx_index,
            )

    @property
    def difficulty(self) -> int:
        """Protocol base difficulty; `calculate_next_difficulty()` gives the next block's."""
        return self._params.initial_difficulty

    @difficulty.setter
    def difficulty(self, new_difficulty: int) -> None:
        if isinstance(new_difficulty, bool) or not isinstance(new_difficulty, int):
            raise ValidationError("Difficulty must be an integer")
        if new_difficulty < 0 or new_difficulty > 256:
            raise ValidationError("Difficulty must be between 0 and 256 bits")
        self._set_params(replace(self._params, initial_difficulty=new_difficulty))

    @property
    def block_reward(self) -> int:
        return self._params.block_reward

    @property
    def mempool(self) -> Tuple[Transaction, ...]:
        with self._lock:
            return tuple(self._mempool.values())

    @property
    def mempool_size(self) -> int:
        return len(self._mempool)

    @property
    def utxo_set(self) -> UTXOSet:
        with self._lock:
            return self._utxo_set.clone()

    @property
    def total_supply(self) -> int:
        """Sum of unspent outputs without cloning the UTXO set."""
        with self._lock:
            return self._utxo_set.total_supply

    def validate_full_chain(self, force: bool = False) -> ChainValidationReport:
        """
        Genesis-to-tip validation of the active chain. The result is cached per tip
        hash, so repeated health checks are O(1) until the tip changes; `force=True`
        re-runs the full O(n) validation regardless.
        """
        with self._lock:
            blocks = list(self._blocks)
            cached = self._health_cache
        tip = blocks[-1].block_hash if blocks else b""
        if not force and cached is not None and cached[0] == tip:
            return cached[1]
        # Validate a snapshot outside the state lock so readers are not blocked.
        report = self._validator.validate_chain(
            blocks, expected_genesis_hash=blocks[0].block_hash if blocks else None
        )
        with self._lock:
            self._health_cache = (tip, report)
        return report

    # ------------------------------------------------------------------------
    # Mempool & Block Mining
    # ------------------------------------------------------------------------

    def submit_transaction_object(self, tx: Transaction) -> bytes:
        """
        Validate a signed transfer transaction against both the current `UTXOSet`
        and existing mempool transactions (preventing mempool double-spends),
        and add it to the mempool.
        """
        with self._lock:
            if not self._blocks:
                raise ValidationError("Cannot submit transaction before Genesis initialization")
            if tx.tx_type == TX_TYPE_COINBASE:
                raise ValidationError("External clients cannot submit coinbase transactions to mempool")
            if tx.timestamp > int(time.time()) + MAX_FUTURE_DRIFT_SECONDS:
                raise ValidationError("Transaction timestamp is too far in the future")

            tx_id = tx.compute_tx_id(self._hasher)
            if tx_id in self._mempool:
                return tx_id  # Idempotent duplicate submission
            if len(self._mempool) >= self._max_mempool_size:
                raise ValidationError(f"Mempool is full ({self._max_mempool_size} transactions)")

            # Incremental validation: only the new tx, against confirmed UTXOs minus
            # outpoints already claimed by pending txs (O(inputs), one signature check).
            outpoints = [tx_in.outpoint_key for tx_in in tx.inputs]
            for op in outpoints:
                if op in self._mempool_spent:
                    raise DoubleSpendError(
                        f"Mempool double-spend: UTXO {op[0].hex()}:{op[1]} is already spent by a pending transaction"
                    )
            available: Dict[Tuple[bytes, int], TxOutput] = {}
            for op in outpoints:
                entry = self._utxo_set.get(op)
                if entry is not None:
                    available[op] = TxOutput(amount=entry.amount, recipient_address=entry.recipient_address)
            validate_block_transactions_no_double_spend(
                [tx],
                available_utxos=available,
                crypto_engine=self._crypto_engine,
                hasher=self._hasher,
            )
            fee = sum(available[op].amount for op in outpoints) - tx.total_output_amount
            if fee < self._min_fee:
                raise ValidationError(f"Fee {fee} is below the minimum relay fee {self._min_fee}")

            self._mempool[tx_id] = tx
            self._mempool_spent.update(outpoints)
            return tx_id

    def submit_transaction(self, tx_bytes: Union[bytes, Transaction]) -> bytes:
        """
        `LedgerQueryInterface` implementation: Deserialize canonical `tx_bytes`
        (or accept `Transaction` object), validate signatures and UTXOs, and add to mempool.
        """
        if isinstance(tx_bytes, Transaction):
            return self.submit_transaction_object(tx_bytes)
        tx = Transaction.from_bytes(tx_bytes)
        return self.submit_transaction_object(tx)

    def mine_pending_transactions(
        self,
        miner_address: Optional[bytes] = None,
        timestamp: Optional[int] = None,
    ) -> Tuple[Block, MiningStats]:
        """
        Assemble pending mempool transactions (plus an optional coinbase reward + fees
        transaction to `miner_address`), mine a valid PoW block, validate it, append
        it to the chain, and update the UTXO hash map.

        The nonce search runs WITHOUT the ledger state lock, so balance/chain reads
        stay responsive while mining. If the tip moves meanwhile, the final append
        fails with ValidationError and the caller may retry.
        """
        with self._mining_lock:
            with self._lock:
                if not self._blocks:
                    raise ValidationError("Cannot mine block before Genesis block is created")
                if not self._mempool and miner_address is None:
                    raise ValidationError("No pending transactions in mempool and no miner_address specified")

                height = len(self._blocks)
                block_ts = int(time.time()) if timestamp is None else timestamp
                staged_utxos = self._utxo_set.clone()
                valid_transfers: List[Transaction] = []
                total_fees = 0

                for tx in self._mempool.values():
                    fee = staged_utxos.apply_transaction(
                        tx,
                        block_index=height,
                        crypto_engine=self._crypto_engine,
                        hasher=self._hasher,
                    )
                    valid_transfers.append(tx)
                    total_fees += fee

                block_txs: List[Transaction] = []
                reward = self._params.block_reward + total_fees
                if miner_address is not None and reward > 0:
                    coinbase_tx = Transaction.create_coinbase(
                        recipient_address=miner_address,
                        amount=reward,
                        timestamp=height,  # height commitment => unique tx_id per block
                    )
                    block_txs.append(coinbase_tx)

                block_txs.extend(valid_transfers)
                target_difficulty = self.calculate_next_difficulty()
                prev_hash = self._blocks[-1].block_hash

            new_block, stats = self._miner.mine_block_with_stats(
                index=height,
                previous_hash=prev_hash,
                transactions=block_txs,
                difficulty=target_difficulty,
                timestamp=block_ts,
            )

            self.append_mined_block(new_block)  # re-validates under the lock
            return new_block, stats

    def append_mined_block(self, block: Block) -> None:
        """Validate and append an externally or locally mined `Block` to the chain tip."""
        with self._lock:
            if not self._blocks:
                if block.index != 0 or block.previous_hash != GENESIS_PREV_HASH:
                    raise ValidationError("First block in ledger must be a valid Genesis block")
                self.load_verified_chain([block])
                return

            expected_idx = len(self._blocks)
            if block.index != expected_idx:
                raise ValidationError(
                    f"Expected block index {expected_idx}, got {block.index}"
                )
            if block.previous_hash != self.tip.block_hash:
                raise ValidationError(
                    f"Block #{block.index} previous_hash does not match current tip"
                )

            block.verify_crystallized_integrity(hasher=self._hasher)
            verify_block_pow(block, hasher=self._hasher)
            check_block_consensus(block, self._blocks, self._params, int(time.time()))

            self._utxo_set.apply_block(
                block,
                max_block_reward=self._params.block_reward,
                crypto_engine=self._crypto_engine,
                hasher=self._hasher,
            )
            self._blocks.append(block)
            self._prune_mempool()
            self._index_block_transactions(block)

    def _prune_mempool(self) -> None:
        """
        Drop mempool txs whose inputs are no longer unspent. Signatures, ownership and
        amounts were checked at submission and an outpoint (tx_id, index) always names
        the same output, so only input availability needs rechecking.
        """
        surviving: Dict[bytes, Transaction] = {}
        spent: Set[Tuple[bytes, int]] = set()
        for tx_id, tx in self._mempool.items():
            ops = [tx_in.outpoint_key for tx_in in tx.inputs]
            if all(op in self._utxo_set and op not in spent for op in ops):
                surviving[tx_id] = tx
                spent.update(ops)
        self._mempool = surviving
        self._mempool_spent = spent

    # ------------------------------------------------------------------------
    # Most-Work Valid-Chain Fork Resolution (Worklet 3.2)
    # ------------------------------------------------------------------------

    def resolve_forks(
        self, candidate_chains: Sequence[Sequence[Block]]
    ) -> ForkResolutionOutcome:
        """
        Worklet 3.2: Resolve competing forks (the course's "longest-valid-chain" rule, measured as most cumulative work).

        Algorithm:
        1. Pin `trusted_genesis = self.genesis_hash` (if the ledger is already initialized)
           so candidate branches from an alien/fabricated Genesis block are rejected (`F-001`).
        2. Validate the currently active chain (`self._blocks`) and every candidate chain
           in `candidate_chains` from Genesis (`block 0`) using `FullChainValidator`.
        3. Any candidate chain that fails validation is rejected and recorded in `rejection_reasons`.
        4. Among all valid chains, select the one with strictly greatest cumulative work
           (sum of 2^difficulty, each difficulty checked against the consensus schedule).
           Equal work keeps the active chain (first-seen rule — `F-006`).
        5. If a candidate chain wins, atomically switch `self._blocks` and `self._utxo_set`
           to the winning chain and prune spent mempool transactions.
        """
        with self._lock:
            trusted_genesis = self.genesis_hash
            best_chain: List[Block] = list(self._blocks)
            current_report = (
                self._validator.validate_chain(
                    best_chain, expected_genesis_hash=trusted_genesis
                )
                if best_chain
                else None
            )
            best_work = (
                current_report.cumulative_pow_work
                if (current_report and current_report.is_valid)
                else 0
            )
            best_utxos = (
                current_report.utxo_set
                if (current_report and current_report.is_valid)
                else UTXOSet()
            )

            switched = False
            valid_count = 1 if (current_report and current_report.is_valid) else 0
            rejected_count = 0
            rejection_reasons: List[str] = []

            for idx, candidate in enumerate(candidate_chains):
                report = self._validator.validate_chain(
                    candidate, expected_genesis_hash=trusted_genesis
                )
                if not report.is_valid:
                    rejected_count += 1
                    rejection_reasons.append(
                        f"Candidate #{idx} (len={len(candidate)}) rejected at block "
                        f"{report.failed_block_index}: {report.error_message}"
                    )
                    continue

                valid_count += 1
                cand_work = report.cumulative_pow_work

                # Most schedule-verified cumulative work wins; ties keep the incumbent.
                if cand_work > best_work:
                    best_chain = list(candidate)
                    best_work = cand_work
                    best_utxos = report.utxo_set
                    switched = True
                    if trusted_genesis is None and best_chain:
                        trusted_genesis = best_chain[0].block_hash

            if switched:
                self._blocks = best_chain
                self._utxo_set = best_utxos
                self._prune_mempool()
                self._rebuild_history_index()

            tip_hex = self._blocks[-1].block_hash_hex if self._blocks else ""
            return ForkResolutionOutcome(
                switched_chain=switched,
                winning_chain_length=len(self._blocks),
                winning_cumulative_work=best_work,
                winning_tip_hash_hex=tip_hex,
                valid_candidates_count=valid_count,
                rejected_candidates_count=rejected_count,
                rejection_reasons=tuple(rejection_reasons),
            )

    # ------------------------------------------------------------------------
    # LedgerQueryInterface Implementation (Worklet 3.3)
    # ------------------------------------------------------------------------

    def get_balance(self, address: bytes) -> int:
        """Return spendable balance for `address` by scanning the UTXO hash map."""
        with self._lock:
            return self._utxo_set.compute_balance(address)

    def get_spendable_utxos(self, address: bytes) -> List[SpendableUTXO]:
        """Return typed `SpendableUTXO` objects for `address`."""
        with self._lock:
            return self._utxo_set.get_spendable_utxos(address)

    def get_utxos_for_address(self, address: bytes) -> List[Dict[str, Any]]:
        """Return serializable dictionary representations of all UTXOs for `address`."""
        with self._lock:
            entries = self._utxo_set.get_utxos_for_address(address)
            return [
                {
                    "tx_id": e.tx_id.hex(),
                    "output_index": e.output_index,
                    "amount": e.amount,
                    "recipient_address": e.recipient_address.hex(),
                    "block_index": e.block_index,
                    "is_coinbase": e.is_coinbase,
                }
                for e in entries
            ]

    def get_merkle_proof(self, block_index: int, tx_id: bytes) -> Optional[MerkleProof]:
        """Produce an O(log2 N) Merkle inclusion proof for `tx_id` in block `block_index`."""
        with self._lock:
            if block_index < 0 or block_index >= len(self._blocks):
                return None
            block = self._blocks[block_index]
            try:
                return block.generate_merkle_proof(tx_id, hasher=self._hasher)
            except ValidationError:
                return None

    def get_transaction_history(self, address: bytes) -> List[Dict[str, Any]]:
        """
        Return a chronological audit trail of all transactions involving `address`
        (as sender or recipient) in O(1) lookup time using the precomputed index.
        """
        with self._lock:
            entries = self._address_history_index.get(address, [])
            return [dict(e) for e in entries]
