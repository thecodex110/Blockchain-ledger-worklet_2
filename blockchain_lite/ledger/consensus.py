"""
Consensus rules: the single source of truth for what makes block N+1 acceptable.

Pure functions only. Protocol parameters are held by the ledger / validator and are
never read from untrusted input (block headers, persisted file headers, RPC params).
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from typing import Protocol, Sequence

from blockchain_lite.interfaces import TX_TYPE_COINBASE, TamperDetectedError, ValidationError
from blockchain_lite.models.block import Block

MEDIAN_TIME_SPAN: int = 11            # blocks used for the median-time-past rule
MAX_FUTURE_DRIFT_SECONDS: int = 2 * 60 * 60


class HeaderLike(Protocol):
    """What the schedule/timestamp rules read: satisfied by `Block` and `BlockHeader`."""

    @property
    def index(self) -> int: ...
    @property
    def timestamp(self) -> int: ...
    @property
    def difficulty(self) -> int: ...


@dataclass(frozen=True)
class ConsensusParams:
    initial_difficulty: int = 8
    block_reward: int = 50
    retarget_interval: int = 0        # 0 = fixed difficulty
    target_block_time_seconds: float = 10.0
    min_difficulty: int = 1
    max_difficulty: int = 24


def expected_difficulty(blocks_so_far: Sequence[HeaderLike], params: ConsensusParams) -> int:
    """Required difficulty for block number `len(blocks_so_far)`, derived only from history."""
    n = len(blocks_so_far)
    interval = params.retarget_interval
    if interval <= 0 or n < interval:
        return params.initial_difficulty
    current = blocks_so_far[-1].difficulty
    if n % interval != 0:
        return current
    actual = blocks_so_far[-1].timestamp - blocks_so_far[-interval].timestamp
    target = interval * params.target_block_time_seconds
    if actual < target * 0.75:
        return min(params.max_difficulty, current + 1)
    if actual > target * 1.33:
        return max(params.min_difficulty, current - 1)
    return current


def median_time_past(prev_blocks: Sequence[HeaderLike]) -> int:
    return statistics.median_low(b.timestamp for b in prev_blocks[-MEDIAN_TIME_SPAN:])


def check_timestamp(block: HeaderLike, prev_blocks: Sequence[HeaderLike], now: int) -> None:
    """Non-genesis blocks: timestamp >= median of the last 11 blocks and <= now + 2h."""
    if block.index == 0:
        return
    mtp = median_time_past(prev_blocks)
    if block.timestamp < mtp:
        raise ValidationError(
            f"Block #{block.index} timestamp {block.timestamp} is before median-time-past {mtp}"
        )
    if block.timestamp > now + MAX_FUTURE_DRIFT_SECONDS:
        raise ValidationError(
            f"Block #{block.index} timestamp {block.timestamp} is more than "
            f"{MAX_FUTURE_DRIFT_SECONDS}s in the future"
        )


def check_block_consensus(
    block: Block, prev_blocks: Sequence[Block], params: ConsensusParams, now: int
) -> None:
    """Difficulty schedule, timestamp bounds and coinbase height commitment for `block`.

    Coinbase format: a non-genesis coinbase stores the block height in its `timestamp`
    field, so two coinbases paying the same miner the same amount never share a tx_id.
    The coinbase reward cap itself is enforced in `UTXOSet.apply_block`.
    """
    required = expected_difficulty(prev_blocks, params)
    if block.difficulty != required:
        raise TamperDetectedError(
            f"Block #{block.index} declares difficulty {block.difficulty}, "
            f"consensus requires {required}"
        )
    check_timestamp(block, prev_blocks, now)
    if block.index > 0:
        for tx in block.transactions:
            if tx.tx_type == TX_TYPE_COINBASE and tx.timestamp != block.index:
                raise ValidationError(
                    f"Block #{block.index} coinbase commits height {tx.timestamp}, expected {block.index}"
                )
