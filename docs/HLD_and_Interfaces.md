# High-Level Design (HLD) & Cross-Worklet Interface Specification

## 1. Architectural Layering & Client-Server Separation

The system enforces a strict four-layer architecture across three parallel worklets with physical separation between the **Digital Wallet (Client)** and the **Blockchain Ledger (Server)**:

```text
+-----------------------------------------------------------------------------------+
|                        CLIENT SIDE (Wallet Layer - Worklet 1)                     |
|  +-----------------------+     +------------------------+     +----------------+  |
|  | Wallet (Private Key d | --> | Transaction Builder &  | --> | WalletClient   |  |
|  | stays strictly local) |     | Canonical Preimage Sig |     | (SPV Verifier) |  |
|  +-----------------------+     +------------------------+     +-------+--------+  |
+-----------------------------------------------------------------------|-----------+
                                                                        |
                     4-Byte Length-Prefixed JSON/Hex RPC over Loopback TCP Sockets
                     (Zero private keys transmitted; max frame size = 16 MiB)
                                                                        |
+-----------------------------------------------------------------------v-----------+
|                        SERVER SIDE (Ledger Layer - Worklets 2 & 3)                |
|  +----------------------------+      +-----------------------------------------+  |
|  | TCPSocketLedgerServer &    | ---> | BlockchainLedger (RLock Synchronized)   |  |
|  | LedgerServerDispatcher     |      | - Active Block Chain (Genesis -> Tip)   |  |
|  +----------------------------+      | - Authoritative UTXOSet Hash Map        |  |
|                                      | - Mempool & Double-Spend Filter         |  |
|                                      +----+---------------+---------------+----+  |
|                                           |               |               |       |
|                 +-------------------------+               |               +----+  |
|                 v                                         v                    v  |
|  +------------------------------+   +---------------------------+   +----------+  |
|  | Worklet 2: Block, MerkleTree |   | Worklet 3: FullChain-     |   | Chain-   |  |
|  | ProofOfWorkMiner & BitLevel- |   | Validator & Longest-Valid |   | Persist- |  |
|  | SHA256 (FIPS 180-4 Bitwise)  |   | Chain Fork Resolution     |   | ence     |  |
|  +------------------------------+   +---------------------------+   +----------+  |
+-----------------------------------------------------------------------------------+
```

1. **Crypto Core & Transaction Layer (`Worklet 1`):** Big-integer modular arithmetic (`number_theory.py`), 40-round Miller–Rabin prime generation, RSA asymmetric cryptography (`asymmetric.py`), canonical `ByteBuffer` serialization (`serialization.py`), and `Transaction` / `TxInput` / `TxOutput` / `Wallet` models (`transaction.py`, `wallet.py`).
2. **Block, Merkle & Proof-of-Work Layer (`Worklet 2`):** Bitwise SHA-256 (`BitLevelSHA256` in `hashing.py`), domain-separated binary `MerkleTree` and $O(\log_2 N)$ `MerkleProof` (`merkle.py`), 88-byte `Block` headers chained via `previous_hash` (`block.py`), and adjustable-difficulty `ProofOfWorkMiner` (`pow.py`).
3. **Validation, Fork Resolution, UTXO & Persistence Layer (`Worklet 3`):** `UTXOSet` hash map (`utxo.py`), `FullChainValidator` (`validator.py`), thread-safe `BlockchainLedger` with most-cumulative-work fork resolution (`chain.py`), the consensus rules every block must satisfy (`consensus.py`: difficulty schedule, timestamp bounds, coinbase height), `ChainPersistence` with atomic `.tmp` + `os.replace` writes and dual-layer on-disk tamper detection (`persistence.py`), and PoW mining benchmarks (`pow_benchmark.py`).
4. **Client-Server Transport Layer (`Integration`):** `WalletClient` (`client.py`, holding private keys locally) communicates with `TCPSocketLedgerServer` (`server.py`) over 4-byte length-prefixed JSON/hex frames (`transport.py`) without any web framework.

## 2. End-to-End Transaction Lifecycle & Data Flow

1. **Keypair & Address Generation (`Worklet 1.2 & 1.3`):** The client generates an RSA keypair $(n, e, d, p, q)$ using 40-round Miller–Rabin probable primes with $|p - q| \ge 2^{\text{prime\_bits}-32}$ and $\gcd(e, \lambda(n)) = 1$. The wallet's 32-byte address is `SHA256(public_key.to_bytes())`.
2. **UTXO Discovery (`Worklet 3.3`):** `WalletClient.get_spendable_utxos()` queries the server's `get_utxos` RPC endpoint, which scans the authoritative `UTXOSet` hash map `(tx_id, output_index) -> UTXOEntry` for unspent outputs locked to the wallet's address.
3. **Deterministic Coin Selection & Signing (`Worklet 1.4`):** `Wallet.create_signed_transfer()` sorts owned UTXOs deterministically by `(amount, tx_id, output_index)`, selects inputs covering `amount + fee`, appends a change output back to `self.address` if `accumulated > amount + fee`, serializes the unsigned `signing_preimage_bytes()`, and signs `BCLT-RSA-SHA256-V1| || pubkey_bytes || | || preimage_bytes` using the local private key $d$.
4. **Mempool Validation (`Worklet 1.5 & 3.3`):** The client sends `submit_transaction(tx_bytes_hex)` over TCP. The server deserializes the canonical `ByteBuffer`, rejects any `COINBASE` submission, verifies RSA signatures and public-key ownership against `UTXOSet`, checks conservation of value ($\sum \text{inputs} \ge \sum \text{outputs}$), and rejects intra-transaction, intra-mempool, or historical double-spends (`DoubleSpendError`).
5. **Proof-of-Work Block Mining (`Worklet 2.1, 2.2, 2.5`):** On `mine_block`, the server prepends a `COINBASE` transaction (`block_reward + total_fees`) at index `0`, builds the domain-separated `MerkleTree` (`0x00` leaf, `0x01` internal node), packs the 80-byte static header prefix, and searches `nonce` values until `int(SHA256(header_88B)) < 2^(256 - D)`.
6. **Atomic State Transition & SPV Verification (`Worklet 2.3, 3.1`):** `UTXOSet.apply_block()` stages all input removals and output insertions on a clone before atomically swapping the dictionary reference. Light clients verify transaction inclusion in $O(\log_2 N)$ steps via `verify_transaction_inclusion_spv()`.

## 3. Canonical Binary Serialization Layouts (`ByteBuffer`)

All integers are encoded in **Unsigned Big-Endian** network byte order. Floating-point values and booleans are rejected at the serializer boundary.

| Structure | Canonical Byte Layout |
| :--- | :--- |
| **`BigInt`** | `[byte_len: uint32 (4B)][unsigned_big_endian_bytes: byte_len B]` (no redundant leading `0x00` bytes; `0` is `0x0000000100`) |
| **`RSAPublicKey`** | `[n: BigInt][e: BigInt]` |
| **`RSAPrivateKey`** | `[n: BigInt][e: BigInt][d: BigInt][p: BigInt][q: BigInt]` |
| **`TxInput` (Unsigned Preimage)** | `[prev_tx_id: 32B][output_index: uint32 (4B)][pubkey_len: uint32 (4B)][sender_pubkey: var]` |
| **`TxInput` (Full Signed)** | `[Unsigned Preimage Bytes][sig_len: uint32 (4B)][signature: var]` |
| **`TxOutput`** | `[amount: uint64 (8B)][recipient_address: 32B]` |
| **`Transaction` (Signing Preimage)** | `[tx_type: uint8 (1B)][timestamp: uint64 (8B)][in_count: uint32 (4B)]{TxInput Unsigned}*[out_count: uint32 (4B)]{TxOutput}*` |
| **`Transaction` (Full Canonical)** | `[tx_type: uint8 (1B)][timestamp: uint64 (8B)][in_count: uint32 (4B)]{TxInput Full}*[out_count: uint32 (4B)]{TxOutput}*` |
| **`Block` Header (88 Bytes Fixed)** | `[index: uint32 (4B)][previous_hash: 32B][merkle_root: 32B][timestamp: uint64 (8B)][difficulty: uint32 (4B)][nonce: uint64 (8B)]` |
| **`Block` (Full Canonical)** | `[88-Byte Header][block_hash: 32B][tx_count: uint32 (4B)]{Transaction Full}*` |
| **`MerkleProof`** | `[tx_id: 32B][tx_index: uint32 (4B)][merkle_root: 32B][step_count: uint32 (4B)]{[dir: uint8 (1B)][sibling_hash: 32B]}*` |
| **On-Disk Persistence (`.bclt`)** | `[Magic: "BCLT" (4B)][Version: uint8 (1B)][Difficulty: uint32 (4B)][Reward: uint64 (8B)][BlockCount: uint32 (4B)]{[BlockLen: uint32][BlockBytes]}*[SHA256_Seal: 32B]` |

## 4. Consensus, Fork Resolution & Atomic Persistence Rules

* **Merkle Odd-Tail Phantom-Index Guard (`F-003`):** When a tree level has an odd number of nodes, the trailing node is duplicated (`working.append(working[-1])`). To prevent an attacker from spoofing a proof for phantom odd index `2k + 1` using leaf `2k`'s hash, `MerkleTree.verify_proof()` rejects any step where `idx % 2 == 1` and `step.sibling_hash == current_hash`.
* **Pinned Genesis Trust Anchor (`F-001`):** `FullChainValidator`, `BlockchainLedger.resolve_forks()`, and `ChainPersistence.load_ledger()` support pinning `expected_genesis_hash` so an attacker or alien fork cannot replace Block `#0` (`Genesis`).
* **Deterministic Fork Resolution (`Worklet 3.2`):** `BlockchainLedger.resolve_forks()` validates every candidate branch from Genesis (`index 0`). Invalid branches (even if longer) are rejected. Every block's difficulty must equal the consensus schedule (`ledger/consensus.py`), so work cannot be self-declared. Among valid branches sharing the active Genesis block, the ledger selects the branch with the strictly greatest cumulative Proof-of-Work (`sum(2^block.difficulty)`), retaining the active chain on equal work.
* **Crash-Safe Atomic Persistence (`Worklet 3.4` & `F-005`):** `ChainPersistence.save_ledger()` writes the sealed `.bclt` binary image to `<target>.tmp`, flushes and calls `os.fsync()`, and atomically replaces the target via `os.replace()`. On reload, `load_ledger()` verifies both the trailing 32-byte SHA-256 envelope seal and full Genesis-to-tip chain validity.

## 5. Empirical Proof-of-Work Mining Experiment (`Worklet 3.5`)

Measured on Python `3.11.2` (`Linux-4.19.0-gvisor-x86_64-with-glibc2.36`, `x86_64`, `2` vCPUs) using `BitLevelSHA256` across `5` independent trials per difficulty level ($D \in \{0, 2, 4, 6, 8, 10\}$):

| Difficulty ($D$) | Expected $E[N] = 2^D$ | Theoretical $\sigma \approx 2^D$ | Mean Hashes ($\pm$ Stdev) | Median Hashes | Min..Max Hashes | Mean Time (ms) | Median Time (ms) | Min..Max Time (ms) | Throughput (H/s) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **0 bits** | `1` | `0.0` | `1.0` ($\pm 0.0$) | `1.0` | `1..1` | `0.933` | `0.903` | `0.89..1.04` | `1,074` |
| **2 bits** | `4` | `3.5` | `3.2` ($\pm 2.8$) | `2.0` | `1..8` | `3.208` | `2.011` | `0.99..8.73` | `1,050` |
| **4 bits** | `16` | `15.5` | `16.0` ($\pm 8.9$) | `18.0` | `5..25` | `16.427` | `18.420` | `4.85..24.61` | `995` |
| **6 bits** | `64` | `63.5` | `101.8` ($\pm 70.1$) | `100.0` | `13..206` | `102.424` | `102.404` | `12.16..205.09` | `1,006` |
| **8 bits** | `256` | `255.5` | `237.0` ($\pm 162.6$) | `236.0` | `5..463` | `248.367` | `252.878` | `4.69..473.91` | `972` |
| **10 bits** | `1,024` | `1,023.5` | `680.4` ($\pm 455.7$) | `478.0` | `390..1,452` | `692.922` | `491.375` | `392.84..1475.68` | `974` |

* **Why Variance Grows Exponentially:** Because each nonce evaluation is an independent Bernoulli trial with success probability $p = 2^{-D}$, the number of trials $N \sim \text{Geom}(p)$ has mean $E[N] = 2^D$ and standard deviation $\sigma_N = \sqrt{1-p}/p \approx 2^D$. Thus dispersion ($\pm 1\sigma$) scales at the same exponential rate as the mean.

### 5.1 Optional fast hash backend (`--fast-hash`)

`blockchain_lite/crypto/fast_hash.py` provides `HashlibSHA256`, a drop-in `HashInterface` that delegates `hash_bytes` to `hashlib.sha256`. It is **opt-in** (dashboard `--fast-hash`, or `hasher=HashlibSHA256()` on `BlockchainLedger` / `ChainPersistence` / `ProofOfWorkMiner`; the TCP server uses whatever hasher its ledger was built with). `BitLevelSHA256` remains `default_hasher` for the educational path and the test-suite. Digests are bit-identical (FIPS vectors and padding boundaries tested in `tests/test_phase11_fast_hash.py`), so a chain mined with either backend validates with the other and persisted `.bclt` files are byte-identical. It is the only package module allowed to import `hashlib` (exempted by name in `TestExclusionsCompliance`).

Measured on Python `3.13.14`, Windows 11, Intel64 Family 6 Model 165 (one run each):

| Measurement | `BitLevelSHA256` (default) | `HashlibSHA256` (`--fast-hash`) | Speed-up |
| :--- | ---: | ---: | ---: |
| Raw SHA-256 over 88-byte PoW headers (3 s window) | 913 H/s | 613,111 H/s | ~672x |
| Mine 20 blocks at difficulty 12 (1 signed transfer each) | 124.1 s | 0.5 s | ~250x |
| Full Genesis-to-tip validation, height 21 | 454 ms | 110 ms | ~4x |

Validation gains less than mining because it is dominated by pure-Python RSA signature verification, which the hash backend does not change. Reproduce with `python -m blockchain_lite.benchmarks.pow_benchmark` (section 4 of its report).

## 6. Security Limitations & Threat Assessment

The full, current threat model (dashboard key custody, RPC auth, SPV trust, key sizes, timing side channels) lives in `SECURITY.md`. The three items below are the original design-level limitations.

1. **Educational RSA Key Sizes (`384`/`512` bits) vs. Production Standards:** To keep pure-Python Miller–Rabin keypair generation fast ($\sim 0.1\text{–}0.4\text{ s}$) during live classroom demonstrations and automated test runs, the default modulus is `512` bits (minimum `384` bits), and signatures use a deterministic domain-separated hash representative (`0x01 || SHA256(domain || pubkey || preimage) || 0xBC`) rather than probabilistic RSA-PSS over $\ge 2048$-bit keys.
2. **Local Privileged Attacker Rewriting `.bclt` Without Pinned Genesis:** If an attacker has write access to the `.bclt` file on disk and the reloading process does not pass an out-of-band `expected_genesis_hash` to `ChainPersistence.load_ledger()`, the attacker can mine a brand-new chain from a forged Genesis block and re-seal the file. Passing `expected_genesis_hash` defeats this attack (`test_phase3_pinned_genesis_trust_anchor_catches_full_file_replacement`).
3. **Single-Server Loopback Model vs. Decentralized P2P Consensus:** The project implements a single-server TCP RPC architecture (`127.0.0.1`) to demonstrate client-server separation (`ARC-001`) without external frameworks. It does not implement peer-to-peer gossip discovery, NAT traversal, Sybil-resistant peer scoring, or Byzantine fault tolerance across mutually distrusting nodes.
