"""
End-to-End Evaluation & Viva Demonstration Runner (`blockchain_lite/cli/demo.py`).

Executes and prints verification evidence for all 3 Worklets, all 5 Viva
Learning-Outcome Checks, and all 5 Common Pitfalls:
1. Worklet 1: Fast modular exponentiation trace, Miller–Rabin primality (Carmichael rejection),
   RSA key generation, canonical transaction signing & verification.
2. Client-Server Separation & Worklet 3.3: Live TCP Socket server + separated Wallet clients
   performing UTXO transfers, PoW block mining, and UTXO balance reconciliation.
3. Worklet 2: Bit-level SHA-256 avalanche analysis (~50% bits flip on 1-bit change) and
   O(log2 N) Merkle inclusion proof verification.
4. Worklet 1.5 & Learning-Outcome Check 2: 1-byte transaction tampering cascade trace and
   intra-block double-spend prevention.
5. Worklet 3.2 & 3.4: Longest-valid-chain fork resolution (rejecting a longer poisoned branch)
   and disk persistence with dual-layer on-disk tamper detection (Pitfall 5).
6. Worklet 3.5: Empirical PoW difficulty vs. mining time benchmark table.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from blockchain_lite.benchmarks.pow_benchmark import (
    format_benchmark_markdown_table,
    run_difficulty_benchmark,
)
from blockchain_lite.crypto.asymmetric import MIN_RSA_MODULUS_BITS, RSACryptoEngine, weak_key_warning
from blockchain_lite.crypto.hashing import default_hasher
from blockchain_lite.crypto.number_theory import (
    is_probable_prime_miller_rabin,
    pow_mod_with_trace,
)
from blockchain_lite.interfaces import TamperDetectedError
from blockchain_lite.ledger.chain import BlockchainLedger
from blockchain_lite.ledger.persistence import ChainPersistence
from blockchain_lite.ledger.validator import FullChainValidator
from blockchain_lite.models.block import Block
from blockchain_lite.models.transaction import Transaction, TxOutput
from blockchain_lite.network.client import TCPSocketTransport, WalletClient
from blockchain_lite.network.server import TCPSocketLedgerServer
from blockchain_lite.network.transport import NetworkRPCError
from blockchain_lite.wallet.wallet import Wallet


def run_complete_demonstration(rsa_bits: int = MIN_RSA_MODULUS_BITS) -> str:
    """Run all evaluation scenarios and return the formatted demonstration transcript."""
    lines: list[str] = []

    def log(text: str = "") -> None:
        lines.append(text)

    log("================================================================================")
    log("  COEP MINI PROJECT 5: BLOCKCHAIN-LITE LEDGER & DIGITAL WALLET — FULL DEMO")
    log("================================================================================")

    # -------------------------------------------------------------------------
    # STAGE 1: Worklet 1 — Number Theory, Miller-Rabin & RSA Key Generation
    # -------------------------------------------------------------------------
    log("\n[1] WORKLET 1: NUMBER THEORY, MILLER-RABIN PRIMALITY & RSA KEY GENERATION")
    base = 0x9876543210FEDCBA9876543210FEDCBA
    exp = (1 << 255) + 123456789
    mod = (1 << 521) - 1
    trace = pow_mod_with_trace(base, exp, mod)
    log(
        f"  * Fast Modular Exponentiation: {trace.exponent_bit_length}-bit exponent computed in "
        f"only {trace.total_modular_ops} modular ops ({trace.squarings} squarings + "
        f"{trace.multiplications} multiplications)."
    )

    carmichaels = [561, 1105, 1729, 2465, 6601]
    carmichael_results = {c: is_probable_prime_miller_rabin(c, rounds=40) for c in carmichaels}
    log(f"  * Miller-Rabin Carmichael Rejection Check: {carmichael_results}")

    crypto = RSACryptoEngine()
    alice_wallet = Wallet.generate("Alice", bit_length=rsa_bits, crypto_engine=crypto)
    bob_wallet = Wallet.generate("Bob", bit_length=rsa_bits, crypto_engine=crypto)
    charlie_wallet = Wallet.generate("Charlie", bit_length=rsa_bits, crypto_engine=crypto)
    miner_wallet = Wallet.generate("Miner", bit_length=rsa_bits, crypto_engine=crypto)
    log(f"  * Generated RSA-{alice_wallet.public_key.bit_length} Wallet 'Alice'   Address: {alice_wallet.address_hex[:24]}...")
    log(f"  * Generated RSA-{bob_wallet.public_key.bit_length} Wallet 'Bob'     Address: {bob_wallet.address_hex[:24]}...")
    log(f"  * Generated RSA-{charlie_wallet.public_key.bit_length} Wallet 'Charlie' Address: {charlie_wallet.address_hex[:24]}...")

    # -------------------------------------------------------------------------
    # STAGE 2: Client-Server Separation over TCP Sockets & UTXO Transfers
    # -------------------------------------------------------------------------
    log("\n[2] CLIENT-SERVER LEDGER & WALLET WORKFLOW OVER TCP SOCKETS")
    ledger = BlockchainLedger(difficulty=6, block_reward=50, crypto_engine=crypto)
    genesis = ledger.create_genesis_block(
        initial_allocations=[
            (alice_wallet.address, 1000),
            (bob_wallet.address, 500),
        ],
        timestamp=1700000000,
    )
    log(f"  * Genesis Block #0 Mined: hash={genesis.block_hash_hex[:24]}... (nonce={genesis.nonce})")

    with TCPSocketLedgerServer(ledger, host="127.0.0.1", port=0, mine_token="demo-mine-token", allow_client_timestamp=True) as server:
        transport = TCPSocketTransport(server.host, server.port)
        alice_client = WalletClient(alice_wallet, transport)
        bob_client = WalletClient(bob_wallet, transport)
        charlie_client = WalletClient(charlie_wallet, transport)
        miner_client = WalletClient(miner_wallet, transport)

        log(f"  * TCP Ledger Server listening on {server.host}:{server.port}")
        log(f"  * Initial Balances (via UTXO scan): Alice={alice_client.get_balance()}, Bob={bob_client.get_balance()}, Charlie={charlie_client.get_balance()}")

        # Alice transfers 320 to Bob (fee 5) and Bob transfers 150 to Charlie (fee 3) in the same block!
        tx1 = alice_client.send_funds(bob_wallet.address, amount=320, fee=5, timestamp=1700000060)
        bob_client.send_funds(charlie_wallet.address, amount=150, fee=3, timestamp=1700000061)
        mine_res = miner_client.request_mining(reward_to_self=True, timestamp=1700000065, auth_token="demo-mine-token")

        log(
            f"  * Mined Block #{mine_res['block_index']} with {mine_res['tx_count']} txs: "
            f"hash={mine_res['block_hash_hex'][:24]}... (nonce={mine_res['nonce']}, "
            f"hashes_tried={mine_res['hashes_tried']})"
        )
        log(
            f"  * Post-Block #1 Balances: Alice={alice_client.get_balance()}, "
            f"Bob={bob_client.get_balance()}, Charlie={charlie_client.get_balance()}, "
            f"Miner={miner_client.get_balance()}"
        )

        # ---------------------------------------------------------------------
        # STAGE 3: Worklet 2 — Bit-Level Avalanche & SPV Merkle Proof
        # ---------------------------------------------------------------------
        log("\n[3] WORKLET 2: BIT-LEVEL HASH AVALANCHE & MERKLE INCLUSION PROOF")
        orig_bytes = tx1.to_bytes()
        mod_bytes = bytearray(orig_bytes)
        mod_bytes[10] ^= 0x01  # Flip 1 bit
        avalanche = default_hasher.analyze_avalanche(orig_bytes, bytes(mod_bytes))
        log(
            f"  * SHA-256 Avalanche Effect: flipping {avalanche.input_bits_flipped} input bit "
            f"flipped {avalanche.output_bits_flipped}/{avalanche.total_output_bits} output bits "
            f"({avalanche.flip_ratio * 100:.1f}%)."
        )

        spv_ok = alice_client.verify_transaction_inclusion_spv(block_index=1, tx_id=tx1.tx_id)
        log(f"  * SPV Light-Client Merkle Proof Verification for Alice's Tx in Block #1: {spv_ok}")

        # ---------------------------------------------------------------------
        # STAGE 4: Double-Spend Prevention over Client-Server RPC
        # ---------------------------------------------------------------------
        log("\n[4] WORKLET 1.5: DOUBLE-SPEND DETECTION & REJECTION")
        alice_utxos = alice_client.get_spendable_utxos()
        ds_tx_a = alice_wallet.create_signed_transfer(
            recipient_address=bob_wallet.address,
            amount=200,
            spendable_utxos=alice_utxos,
            timestamp=1700000120,
        )
        ds_tx_b = alice_wallet.create_signed_transfer(
            recipient_address=charlie_wallet.address,
            amount=250,
            spendable_utxos=alice_utxos,
            timestamp=1700000121,
        )
        transport.send_request("submit_transaction", {"tx_bytes_hex": ds_tx_a.to_bytes().hex()})
        try:
            transport.send_request("submit_transaction", {"tx_bytes_hex": ds_tx_b.to_bytes().hex()})
        except NetworkRPCError as exc:
            log(f"  * Second conflicting spend of same UTXO rejected by server: {exc}")
        miner_client.request_mining(reward_to_self=True, timestamp=1700000125, auth_token="demo-mine-token")

    # -------------------------------------------------------------------------
    # STAGE 5: 1-Byte Tamper Cascade, Fork Resolution & On-Disk Tamper Check
    # -------------------------------------------------------------------------
    log("\n[5] WORKLET 3: 1-BYTE TAMPER CASCADE, FORK RESOLUTION & PERSISTENCE")
    validator = FullChainValidator(crypto_engine=crypto, max_block_reward=50)
    tampered_blocks = list(ledger.blocks)
    b1 = tampered_blocks[1]
    orig_t1 = b1.transactions[1]
    corrupted_t1 = Transaction(
        tx_type=orig_t1.tx_type,
        timestamp=orig_t1.timestamp,
        inputs=orig_t1.inputs,
        outputs=(
            TxOutput(amount=999, recipient_address=bob_wallet.address),  # Altered 320 -> 999
            orig_t1.outputs[1],
        ),
    )
    tampered_blocks[1] = Block(
        index=b1.index,
        previous_hash=b1.previous_hash,
        merkle_root=b1.merkle_root,
        timestamp=b1.timestamp,
        difficulty=b1.difficulty,
        nonce=b1.nonce,
        transactions=(b1.transactions[0], corrupted_t1, b1.transactions[2]),
        block_hash=b1.block_hash,
    )
    cascade = validator.trace_tamper_cascade(
        original_chain=ledger.blocks,
        tampered_chain=tampered_blocks,
        block_index=1,
        tx_index=1,
    )
    log("  * 1-Byte Tamper in Block #1 Tx #1:")
    log(f"    - Signature Valid After Tamper : {cascade.signature_valid_after_tamper}")
    log(f"    - Merkle Root Matches Header   : {cascade.merkle_root_matches_header}")
    log(f"    - Downstream Broken Blocks     : {cascade.downstream_broken_block_indices}")
    fork_res = ledger.resolve_forks([tampered_blocks])
    log(f"  * Poisoned Fork Rejected by Consensus: switched={fork_res.switched_chain}, rejected={fork_res.rejected_candidates_count}")

    persistence = ChainPersistence(crypto_engine=crypto, params=ledger.params)
    with tempfile.TemporaryDirectory() as tmpdir:
        disk_path = Path(tmpdir) / "chain.bclt"
        persistence.save_ledger(ledger, disk_path)
        reloaded = persistence.load_ledger(disk_path)
        log(f"  * Disk Persistence Reload Verified: height={reloaded.height}, valid={reloaded.validate_full_chain().is_valid}")

        # Corrupt 1 byte on disk
        raw_disk = bytearray(disk_path.read_bytes())
        raw_disk[len(raw_disk) // 2] ^= 0xFF
        disk_path.write_bytes(bytes(raw_disk))
        try:
            persistence.load_ledger(disk_path)
        except TamperDetectedError as exc:
            log(f"  * On-Disk Tampering Caught on Reload: {exc}")

    # -------------------------------------------------------------------------
    # STAGE 6: Worklet 3.5 — PoW Difficulty vs. Mining Time Benchmark
    # -------------------------------------------------------------------------
    log("\n[6] WORKLET 3.5: PROOF-OF-WORK DIFFICULTY VS. MINING TIME BENCHMARK")
    bench_rows = run_difficulty_benchmark(difficulties=(0, 4, 8, 10), trials_per_difficulty=3)
    log(format_benchmark_markdown_table(bench_rows))
    log("\n================================================================================")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Blockchain-Lite 6-stage demonstration")
    parser.add_argument("--rsa-bits", type=int, default=MIN_RSA_MODULUS_BITS,
                        help=f"RSA modulus size for demo wallets (default {MIN_RSA_MODULUS_BITS}; educational)")
    args = parser.parse_args()
    banner = weak_key_warning(args.rsa_bits)
    if banner:
        print(banner, file=sys.stderr)
    print(run_complete_demonstration(rsa_bits=args.rsa_bits))


if __name__ == "__main__":
    main()
