"""
Proof-of-Work Difficulty vs. Mining Time Benchmark Suite (Worklet 3.5 & Phase 7).

Satisfies:
- Worklet 3.5: "Measure how difficulty affects mining time."
- Phase 7 Requirements:
  * Confirm Proof-of-Work target rule: `int(SHA256(header_88_bytes)) < 2^(256 - D)`.
  * Record multi-trial statistics (mean, median, min, max, sample standard deviation).
  * Capture Python runtime and platform environment metadata.
  * Explain Geometric-distribution variance (E[X] = 2^D, SD[X] = sqrt(1 - 2^-D) * 2^D ~ 2^D).
  * Provide a standalone CLI entrypoint (`python3 -m blockchain_lite.benchmarks.pow_benchmark`)
    that never stalls normal application startup.
"""

from __future__ import annotations

import os
import platform
import statistics
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

from blockchain_lite.crypto.hashing import default_hasher
from blockchain_lite.interfaces import GENESIS_PREV_HASH, HashInterface
from blockchain_lite.ledger.pow import ProofOfWorkMiner
from blockchain_lite.models.transaction import Transaction


@dataclass(frozen=True)
class DifficultyBenchmarkRow:
    """
    Aggregated empirical mining metrics for a single Proof-of-Work difficulty setting `D`.
    """
    difficulty_bits: int
    trials: int
    theoretical_expected_hashes: int
    theoretical_stddev_hashes: float
    mean_hashes_tried: float
    median_hashes_tried: float
    stdev_hashes_tried: float
    mean_elapsed_ms: float
    median_elapsed_ms: float
    stdev_elapsed_ms: float
    min_elapsed_ms: float
    max_elapsed_ms: float
    mean_hashes_per_sec: float
    sample_block_hash_hex: str


def get_benchmark_environment_metadata() -> Dict[str, str]:
    """Capture runtime environment details for reproducible academic reporting."""
    return {
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "cpu_count": str(os.cpu_count() or 1),
        "hash_engine": "BitLevelSHA256 (Pure-Python 32-bit FIPS 180-4)",
        "pow_target_rule": "int_be(SHA256(header_88_bytes)) < 2^(256 - D)",
    }


def run_difficulty_benchmark(
    difficulties: Sequence[int] = (0, 2, 4, 6, 8, 10),
    trials_per_difficulty: int = 5,
    hasher: HashInterface = default_hasher,
) -> List[DifficultyBenchmarkRow]:
    """
    Measure how Proof-of-Work difficulty `D` (in required leading zero bits) affects
    the number of nonce evaluations and mining time across `trials_per_difficulty`
    independent block headers.

    Statistical & Mathematical Model:
    - Because SHA-256 behaves as a pseudo-random oracle, each nonce evaluation is an
      independent Bernoulli trial with success probability `p = 2^(-D)`.
    - The number of hash trials `X` required to mine a block follows a Geometric
      distribution `X ~ Geom(p)` supported on `{1, 2, 3, ...}`:
        * Theoretical Mean: `E[X] = 1 / p = 2^D`
        * Theoretical Standard Deviation: `SD[X] = sqrt(1 - p) / p = 2^D * sqrt(1 - 2^(-D))`
    - Consequently, high variance across individual trials (with standard deviation
      nearly equal to the mean `2^D`) is an intrinsic mathematical property of
      memoryless Proof-of-Work mining.
    """
    if trials_per_difficulty < 1:
        raise ValueError("trials_per_difficulty must be >= 1")

    miner = ProofOfWorkMiner(hasher=hasher)
    dummy_addr = hasher.hash_bytes(b"benchmark-miner-address")
    results: List[DifficultyBenchmarkRow] = []

    for diff in difficulties:
        if diff < 0 or diff > 20:
            raise ValueError(f"Benchmark difficulty {diff} outside practical range [0, 20]")

        hashes_list: List[int] = []
        elapsed_ms_list: List[float] = []
        rates_list: List[float] = []
        sample_hash = ""

        for trial in range(trials_per_difficulty):
            tx = Transaction.create_coinbase(
                recipient_address=dummy_addr,
                amount=50 + trial + (diff * 100),
                timestamp=1700000000 + trial + (diff * 1000),
            )
            _, stats = miner.mine_block_with_stats(
                index=trial,
                previous_hash=GENESIS_PREV_HASH,
                transactions=[tx],
                difficulty=diff,
                timestamp=1700000000 + trial + (diff * 1000),
            )
            hashes_list.append(stats.hashes_tried)
            elapsed_ms_list.append(stats.elapsed_seconds * 1000.0)
            rates_list.append(stats.hashes_per_second)
            if trial == 0:
                sample_hash = stats.block_hash_hex

        p = 1.0 / (1 << diff)
        theo_expected = 1 << diff
        theo_stddev = ((1.0 - p) ** 0.5) / p if diff > 0 else 0.0

        stdev_hashes = statistics.stdev(hashes_list) if len(hashes_list) >= 2 else 0.0
        stdev_ms = statistics.stdev(elapsed_ms_list) if len(elapsed_ms_list) >= 2 else 0.0

        results.append(
            DifficultyBenchmarkRow(
                difficulty_bits=diff,
                trials=trials_per_difficulty,
                theoretical_expected_hashes=theo_expected,
                theoretical_stddev_hashes=theo_stddev,
                mean_hashes_tried=statistics.mean(hashes_list),
                median_hashes_tried=float(statistics.median(hashes_list)),
                stdev_hashes_tried=stdev_hashes,
                mean_elapsed_ms=statistics.mean(elapsed_ms_list),
                median_elapsed_ms=float(statistics.median(elapsed_ms_list)),
                stdev_elapsed_ms=stdev_ms,
                min_elapsed_ms=min(elapsed_ms_list),
                max_elapsed_ms=max(elapsed_ms_list),
                mean_hashes_per_sec=statistics.mean(rates_list),
                sample_block_hash_hex=sample_hash,
            )
        )

    return results


def compare_hasher_throughput(seconds: float = 2.0) -> List[Tuple[str, float]]:
    """
    Raw SHA-256 throughput (hashes/second) over 88-byte PoW headers for the pure-Python
    `BitLevelSHA256` and the optional hashlib-backed `HashlibSHA256`. The fast backend
    is imported here, on demand only, so the default import graph never loads hashlib.
    """
    from blockchain_lite.crypto.fast_hash import HashlibSHA256

    results: List[Tuple[str, float]] = []
    for hasher in (default_hasher, HashlibSHA256()):
        count, start = 0, time.perf_counter()
        deadline = start + seconds
        while time.perf_counter() < deadline:
            for nonce in range(64):
                hasher.hash_bytes(b"\x00" * 80 + nonce.to_bytes(8, "big"))
            count += 64
        results.append((type(hasher).__name__, count / (time.perf_counter() - start)))
    return results


def format_benchmark_markdown_table(rows: Sequence[DifficultyBenchmarkRow]) -> str:
    """Format benchmark results into a clean Markdown table for reports and CLI output."""
    lines = [
        "| Difficulty (Zero Bits) | Expected Hashes (2^D) | Mean Actual Hashes (±SD) | Median Hashes | Mean Mining Time (ms) | Min..Max Time (ms) | Hash Rate (H/s) | Sample Winning Hash Prefix |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for r in rows:
        lines.append(
            f"| {r.difficulty_bits} bits | {r.theoretical_expected_hashes:,} | "
            f"{r.mean_hashes_tried:,.1f} (±{r.stdev_hashes_tried:,.1f}) | "
            f"{r.median_hashes_tried:,.1f} | {r.mean_elapsed_ms:.3f} ms | "
            f"{r.min_elapsed_ms:.2f}..{r.max_elapsed_ms:.2f} ms | "
            f"{r.mean_hashes_per_sec:,.0f} H/s | `{r.sample_block_hash_hex[:16]}...` |"
        )
    return "\n".join(lines)


def generate_full_experiment_report(
    difficulties: Sequence[int] = (0, 2, 4, 6, 8, 10),
    trials_per_difficulty: int = 5,
) -> str:
    """Run the experiment and produce a complete, self-contained report with metadata and analysis."""
    meta = get_benchmark_environment_metadata()
    rows = run_difficulty_benchmark(
        difficulties=difficulties,
        trials_per_difficulty=trials_per_difficulty,
    )
    table = format_benchmark_markdown_table(rows)
    lines = [
        "# Worklet 3.5 — Proof-of-Work Difficulty vs. Mining Time Experiment Report",
        "",
        "## 1. Experimental Environment & Methodology",
        f"- **Python Version:** `{meta['python_version']}`",
        f"- **Platform / Architecture:** `{meta['platform']}` (`{meta['architecture']}`, `{meta['cpu_count']}` vCPUs)",
        f"- **Hash Implementation:** `{meta['hash_engine']}`",
        f"- **PoW Target Rule:** `{meta['pow_target_rule']}`",
        f"- **Trials per Difficulty Setting:** `{trials_per_difficulty}` independent block headers per difficulty level",
        "",
        "## 2. Empirical Results vs. Theoretical Predictions",
        table,
        "",
        "## 3. Analysis of Scaling & Observed Variance",
        "- **Exponential Scaling (`2^D` Law):** Each additional required leading zero bit halves the valid target space `T(D) = 2^(256 - D)`, doubling the expected number of SHA-256 evaluations `E[X] = 2^D`.",
        "- **Why Variance Is High Across Individual Runs:** Because SHA-256 acts as a pseudo-random oracle, each nonce check is an independent Bernoulli trial with success probability `p = 2^(-D)`. The trial count `X` follows a **Geometric distribution** with mean `2^D` and theoretical standard deviation `sqrt(1 - p) / p ≈ 2^D`. Because the standard deviation equals the mean, individual blocks at the same difficulty naturally vary from a few hashes (lucky early nonce) to several multiples of `2^D`.",
    ]
    return "\n".join(lines)


def format_hasher_comparison(rows: Sequence[Tuple[str, float]]) -> str:
    base = rows[0][1]
    lines = ["| Hash backend | Throughput (H/s) | Speed-up vs pure Python |", "| :--- | ---: | ---: |"]
    lines += [f"| {name} | {hps:,.0f} | {hps / base:,.0f}x |" for name, hps in rows]
    return "\n".join(lines)


if __name__ == "__main__":
    # The report uses ±/≈; legacy Windows code pages (cp1252) cannot encode them.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print(generate_full_experiment_report())
    print("\n## 4. Hash Backend Throughput (88-byte PoW headers)")
    print(format_hasher_comparison(compare_hasher_throughput()))
