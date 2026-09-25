# Protocol, Serialization & Architecture Specification

**Project:** Mini Project 5 — Blockchain-Lite Ledger & Digital Wallet  
**Institution:** COEP Technological University · Department of Computer Science & Engineering  
**Status:** Protocol version `1` (wire format unchanged since Phase 1). Consensus rules in §6.1–§7 were tightened on 2026-10-15 (audit fixes D1, D2, D3, D8); chains that relied on self-declared difficulty, header-defined rewards, or non-height-committing coinbases are no longer valid.
**Scope:** Educational system; see `SECURITY.md` for the threat model. RPC methods are listed in `docs/RPC_Reference.md`.

## 1. Authoritative Binary Serialization Format (`ByteBuffer`)

All domain models (`RSAPublicKey`, `RSAPrivateKey`, `TxInput`, `TxOutput`, `Transaction`, `Block`, `MerkleProof`, and `.bclt` persistence files) use deterministic **Unsigned Big-Endian** binary serialization via `blockchain_lite.serialization.ByteBuffer`:

| Primitive / Type | Wire Representation | Validation Invariants |
| :--- | :--- | :--- |
| `uint8` | 1-byte unsigned integer (`0 .. 255`) | Rejects `bool`, `float`, and values outside `[0, 255]` |
| `uint32` | 4-byte big-endian unsigned integer (`>I`) | Rejects `bool`, `float`, and values outside `[0, 2^32 - 1]` |
| `uint64` | 8-byte big-endian unsigned integer (`>Q`) | Rejects `bool`, `float`, and values outside `[0, 2^64 - 1]` |
| `hash32` / `bytes32` | Fixed 32-byte raw digest | Must be `bytes` or `bytearray` of exact length `32` |
| `var_bytes` | `[len: uint32 (4B)][raw_bytes: len B]` | Rejects `len > max_length` or buffer underflow |
| `BigInt` | `[byte_len: uint32 (4B)][big_endian_bytes]` | `0` encodes as `0x00` (1B); positive integers have no leading `0x00` byte |

At the end of every object deserialization (`from_bytes`), `reader.assert_exhausted()` is mandatory and raises `SerializationError` if any trailing unparsed bytes remain.

## 2. Hashing Algorithm & Interface (`Worklet 2.4`)

* **Algorithm:** Custom bit-level FIPS 180-4 **SHA-256** (`BitLevelSHA256` in `blockchain_lite/crypto/hashing.py`).
* **Bit-Level Operations:** 32-bit word masking (`MASK32 = 0xFFFFFFFF`), circular right rotation (`rotr32`), logical right shift (`shr32`), modulo-$2^{32}$ addition (`add32`), bitwise multiplexer (`ch_gate`), and bitwise majority voter (`maj_gate`).
* **Padding:** Merkle–Damgård strengthening (`0x80` byte followed by `0x00` bytes until length $\equiv 56 \pmod{64}$, followed by 64-bit big-endian bit-length).
* **Address Derivation:** `address = SHA256(public_key.to_bytes())` (32 bytes / 64 hex chars).
* **Optional backend:** `HashlibSHA256` (`crypto/fast_hash.py`, opt-in via `--fast-hash` or `hasher=`) produces bit-identical digests, so it never changes any wire byte, `tx_id`, Merkle root or block hash.

## 3. Asymmetric Cryptography & Signature Scheme (`Worklet 1.1, 1.2 & 1.4`)

* **Key Generation:**
  * Two distinct probable primes $p \ne q$ generated via CSPRNG (`os.urandom`) rejection sampling, small-prime trial division ($p \le 997$), and 40 rounds of Miller–Rabin testing (`is_probable_prime_miller_rabin`).
  * Fermat distance guard: $|p - q|$ must have bit length $\ge (\text{prime\_bits} - 32)$.
  * Modulus $n = p \cdot q$, public exponent $e = 65537$, Carmichael totient $\lambda(n) = \text{lcm}(p-1, q-1)$ with $\gcd(e, \lambda(n)) = 1$, private exponent $d = e^{-1} \pmod{\lambda(n)}$ computed via iterative `extended_gcd`.
  * Key sizes: Minimum `384` bits (for fast unit test fixtures), default `512` bits (`1024`/`2048` bits supported via `bit_length` parameter). Explicitly documented as an educational implementation (real-world financial deployments require $\ge 2048$-bit RSA).
* **Deterministic Domain-Separated Educational RSA Signature Construction:**
  * Given `public_key` and canonical `message_bytes`, compute:
    $$\text{digest} = \text{SHA256}(\texttt{b"BCLT-RSA-SHA256-V1|"} \parallel \text{public\_key.to\_bytes()} \parallel \texttt{b"|"} \parallel \text{message\_bytes})$$
  * Form the 34-byte (272-bit) integer representative:
    $$m_{\text{int}} = \text{int\_from\_big\_endian}(\texttt{b"\textbackslash x01"} \parallel \text{digest} \parallel \texttt{b"\textbackslash xbc"})$$
  * Sign: $s = m_{\text{int}}^d \pmod n$ via `pow_mod`, followed by fault-attack self-verification $s^e \pmod n == m_{\text{int}}$.
  * Verify: Check $1 < s < n$ and $s^e \pmod n == m_{\text{int}}$.

## 4. Transaction Signing Payload, ID Rules & Value Conservation (`Worklet 1.3–1.5`)

* **Signing Preimage (`Transaction.signing_preimage_bytes()`):**
  `[tx_type: uint8 (1B)][timestamp: uint64 (8B)][in_count: uint32 (4B)]{ [prev_tx_id: 32B][output_index: uint32 (4B)][pubkey_len: uint32 (4B)][sender_pubkey: var] }*[out_count: uint32 (4B)]{ [amount: uint64 (8B)][recipient_address: 32B] }*`
  The `signature` field of every `TxInput` is strictly excluded from `signing_preimage_bytes()`.
* **Full Transaction Serialization (`Transaction.to_bytes()`):**
  Includes each `TxInput`'s `[sig_len: uint32 (4B)][signature: var]` immediately after its `sender_pubkey`.
* **Transaction ID (`tx_id`):** `tx_id = SHA256(tx.to_bytes())` (32 bytes).
* **Value Conservation & Ownership Rules:**
  * Every `TxOutput.amount` must be an integer in `[1, MAX_TOKEN_SUPPLY]`.
  * `TX_TYPE_COINBASE (0)`: Allowed only at `block.transactions[0]`; `len(inputs) == 0`; for blocks at `index > 0`, `sum(coinbase.outputs) <= block_reward + sum(transfer_fees_in_block)`, where `block_reward` is a protocol parameter held by the validator (never read from a file header).
  * **Coinbase height commitment (BIP34-style, D3):** for blocks at `index > 0`, the coinbase `timestamp` field MUST equal `block.index`. This makes every coinbase's `tx_id` unique (same miner, same reward, same second no longer collide) without changing the serialization. The genesis coinbase (index 0) keeps a real timestamp.
  * `TX_TYPE_TRANSFER (1)`: `len(inputs) >= 1`; no duplicate `(prev_tx_id, output_index)` within the transaction or across any transactions in the same block (`DoubleSpendError`); every referenced `(prev_tx_id, output_index)` must exist in the active `UTXOSet`; `SHA256(tx_in.sender_pubkey) == utxo.recipient_address` (`TamperDetectedError`); `sum(inputs) >= sum(outputs)` with `fee = sum(inputs) - sum(outputs)`.

## 5. Merkle Tree & Inclusion Proof Protocol (`Worklet 2.2 & 2.3`)

* **Leaf Hash:** `H(0x00 || tx_id)` (32 bytes).
* **Internal Parent Hash:** `H(0x01 || left_hash || right_hash)` (32 bytes, non-commutative).
* **Single-Transaction Block ($N = 1$):** `merkle_root = H(0x00 || tx_0.tx_id)`; proof has `0` steps.
* **Odd Leaf Count ($k > 1$ odd at any level):** Trailing node `level[-1]` is duplicated to pair with itself (`hash_merkle_internal(level[-1], level[-1])`).
* **Inclusion Proof Verification & Odd-Tail Spoof Guard (`F-003`):**
  * At each step, if `idx` is even, `step.direction` must be `"RIGHT"`; if `idx` is odd, `step.direction` must be `"LEFT"`.
  * **Odd-Tail Phantom Index Guard:** At leaf level (`step_idx == 0`), if `idx` is odd (`step.direction == "LEFT"`) and `step.sibling_hash == current_hash`, the proof is rejected (`False`) because distinct valid transactions in a block cannot have identical leaf hashes, so a leaf-level left sibling equal to `current_hash` only occurs when spoofing the duplicated phantom index $N$ of an odd-sized transaction list.

## 6. Block Header, Proof-of-Work & Genesis Trust Model (`Worklet 2.1, 2.5, 3.1`)

* **88-Byte Fixed Block Header (`Block.header_bytes()`):**
  `[index: uint32 (4B)][previous_hash: 32B][merkle_root: 32B][timestamp: uint64 (8B)][difficulty: uint32 (4B)][nonce: uint64 (8B)]`
* **Block Hash (`block_hash`):** `SHA256(header_bytes)` (32 bytes).
* **Proof-of-Work Target Rule:** Difficulty $D \in [0, 256]$ specifies required leading zero bits. A block header hash is valid iff `int.from_bytes(block_hash, "big") < (1 << (256 - D))`.
* **Genesis Block & Trust Anchor (`F-001`):**
  * Block `0` must have `index == 0` and `previous_hash == b"\x00" * 32`.
  * When a `trusted_genesis_hash` is configured (or already established by an initialized `BlockchainLedger`), any candidate chain in `FullChainValidator`, `BlockchainLedger.resolve_forks()`, or `ChainPersistence.load_ledger()` whose `blocks[0].block_hash != trusted_genesis_hash` is rejected with `TamperDetectedError`.

### 6.1 Consensus Rules (`blockchain_lite/ledger/consensus.py`)

Protocol parameters (`ConsensusParams`) are held by `BlockchainLedger` / `FullChainValidator` / `ChainPersistence`, supplied by the caller (defaults: `initial_difficulty=8`, `block_reward=50`, `retarget_interval=0`, `target_block_time_seconds=10`, `min_difficulty=1`, `max_difficulty=24`). They are fixed once Genesis exists. Every block, whether appended, loaded, or part of a fork candidate, must satisfy `check_block_consensus`:

* **Difficulty schedule (D1):** `block.difficulty == expected_difficulty(blocks_before_it, params)`.
  * Retargeting disabled (`retarget_interval == 0`), or fewer than `retarget_interval` blocks: `initial_difficulty`.
  * Height not a multiple of the interval: the previous block's difficulty.
  * Height a multiple of the interval: `actual = ts[-1] - ts[-interval]`, `target = interval * target_block_time_seconds`; `+1` if `actual < 0.75 * target`, `-1` if `actual > 1.33 * target` (clamped to `[min_difficulty, max_difficulty]`), else unchanged.
  * A block declaring any other difficulty, higher or lower, is rejected (`TamperDetectedError`).
* **Timestamps (D8):** for `index > 0`, `block.timestamp >= median_low(timestamps of the previous 11 blocks)` and `block.timestamp <= now + 7200 s`. Equality with the median is allowed so several blocks mined in the same second stay valid. Genesis is exempt. Mempool transactions more than 2 h in the future are rejected.
* **Coinbase height:** see §4.
* **Reward cap:** see §4 (enforced in `UTXOSet.apply_block`).

## 7. Fork Resolution (`Worklet 3.2`)

* **Validation first:** every candidate is validated from Genesis with `FullChainValidator` (genesis pinned to the active chain's genesis when initialized, and all §6.1 rules applied). Invalid candidates are rejected regardless of length.
* **Selection rule:** among valid chains, choose the one with strictly greater cumulative work $\sum 2^{B_i.\text{difficulty}}$. Because each difficulty is checked against the schedule, this work cannot be self-declared.
* **Tie rule (`F-006`):** on equal cumulative work the active chain is kept (first-seen stability). Length is not used as a separate criterion.

## 8. Persistence & Atomic Recovery Semantics (`Worklet 3.4`)

* **Wire Format (`.bclt`):**
  `[Magic: b"BCLT" (4B)][Version: uint8 (1B)][Difficulty: uint32 (4B)][BlockReward: uint64 (8B)][BlockCount: uint32 (4B)]{ [BlockLen: uint32 (4B)][BlockBytes: var] }*[FileIntegritySeal: 32B (SHA256 of preceding bytes)]`
* **Atomic Save (`F-005`):** `ChainPersistence.save_ledger()` writes to `<target>.tmp`, flushes, and atomically replaces `<target>` via `os.replace()` so an interrupted write never corrupts the previous valid ledger file.
* **Dual-Layer Reload Validation:** Verifies the trailing 32-byte `FileIntegritySeal` AND runs `FullChainValidator.validate_chain_or_raise()` (including `expected_genesis_hash` if supplied) before constructing the active `BlockchainLedger` and `UTXOSet`.
* **Untrusted header fields (D2):** the header's `Difficulty` and `BlockReward` are informational. `load_ledger(path, params=...)` validates under the caller's `ConsensusParams` (or the engine's defaults) and rejects (`TamperDetectedError`) any file whose header values disagree with them. The file format and `Version = 1` are unchanged.

## 9. Client-Server Framing & Error Handling (`ARC-001`)

* **Framing:** `[frame_byte_len: uint32 (4B big-endian)][utf8_json_bytes]` over loopback TCP (`127.0.0.1`), capped at `MAX_FRAME_BYTES = 16 MB`.
* **Security Boundary:** Private keys never leave `WalletClient`. Any server request containing `"private_key"` or `"private_key_hex"` in `params` is rejected with `SecurityViolationError`.
* **Input Hardening (`F-002`, `F-006`):** Malformed JSON/UTF-8 frames, missing required parameter keys, out-of-range integers, invalid hex strings, or mining when the next block's scheduled difficulty exceeds `MAX_RPC_MINING_DIFFICULTY = 20` return deterministic `{"ok": False, "error": {"type": "<ErrorType>", "message": "<Reason>"}}` responses without crashing the server thread.
* **Mining policy:** `mine_block` is disabled unless the server was started with a `mine_token`, and then requires a matching `auth_token` param (constant-time compare). Client-chosen block timestamps are rejected unless the server opts in with `allow_client_timestamp=True` (used by deterministic tests and the CLI demo).
* **Concurrency:** no dispatcher-wide lock; `BlockchainLedger` guards its own state and searches nonces outside its state lock, so reads stay responsive during mining.
* **Light clients:** `get_headers` serves raw 88-byte headers; `WalletClient.fetch_verified_headers` checks links, PoW, the difficulty schedule and timestamps from a trusted genesis hash before any Merkle root is trusted (§6.1 applies to headers too).
