# Security Policy, Known Limitations & Threat Model

**Blockchain-Lite is educational software. Do not use it to protect real assets.**
It exists to show how hashing, signatures, Merkle trees, proof-of-work and UTXO validation fit
together, implemented from first principles in pure Python.

## Reporting

This is a course project with no production deployment. Report issues to the project maintainers
through your course channel or the repository's issue tracker. Please do not include real secrets.

## What is defended (and tested)

| Threat | Defence | Test |
| :--- | :--- | :--- |
| Rewriting history with cheap blocks (self-declared difficulty) | Difficulty must equal the schedule derived from history; fork choice by schedule-verified cumulative work | `tests/test_attack_scenarios.py::test_d1_*` |
| Forged `.bclt` file (inflated reward / difficulty in header) | Protocol parameters come from the caller; disagreeing headers are rejected; full re-validation from genesis; optional pinned genesis hash | `test_d2_*`, `test_phase3_pinned_genesis_*` |
| Coinbase `tx_id` collisions | Coinbase commits block height | `test_d3_*` |
| Timestamp manipulation | Median-time-past lower bound, +2 h future bound | `test_d8_*` |
| Cross-site requests to the dashboard (CSRF) | Per-run API token, JSON-only POSTs, no CORS wildcard | `test_d5_*` |
| Malformed or oversized HTTP bodies, leaked exception text | Content-Length validation, 64 KiB cap, generic 500s | `test_d6_*` |
| Tampered transactions or blocks | Signatures, Merkle roots, header hashes, prev-hash links; every single-byte mutation of a real block/tx is rejected | `tests/test_phase12_serialization_properties.py` |
| Unauthenticated mining over RPC | `mine_block` disabled unless the server has a `mine_token` | `tests/test_phase9_core_engineering.py` |
| Secrets in logs | Logs record events and error types only; tokens never logged | `test_logs_*`, `test_rpc_logs_*` |

## Known limitations (by design or out of scope)

1. **RSA key sizes.** Demo wallets default to 384-bit keys (`--rsa-bits` changes this; anything under
   2048 prints a warning). 384/512-bit RSA can be factored with modest resources. 2048-bit keys work
   end-to-end (`test_2048_bit_wallet_end_to_end`).
2. **Custom signature scheme.** Deterministic hash-and-sign with a 272-bit representative
   (`0x01 || SHA256(domain || pubkey || preimage) || 0xBC`), not RSA-PSS or ECDSA, and not reviewed.
3. **Not constant-time.** `pow_mod` and the pure-Python SHA-256 leak timing. Never use them where an
   attacker can measure execution time.
4. **Dashboard holds private keys.** The web dashboard signs transfers server-side with demo wallets'
   keys. The API token prevents cross-site abuse, but anyone who can read the token (startup output,
   `docker logs`) can spend demo funds. It binds to `127.0.0.1` by default and warns loudly otherwise;
   Docker Compose publishes it on the host's loopback only.
5. **RPC is unauthenticated except for mining.** Reads and `submit_transaction` are open to anyone who
   can reach the port (signed transactions are safe to submit; the server is loopback by default).
   There is no TLS: use only on trusted networks.
6. **SPV trust.** Without `trusted_genesis_hash`, `verify_transaction_inclusion_spv` trusts the Merkle
   root reported by the server. With it, the client verifies the header chain from genesis, but still
   cannot detect a withheld heavier chain or a correctly mined fork at the requested height
   (`test_limitation_validly_mined_fork_at_tip_is_not_detectable`).
7. **Single process, single server.** No peer-to-peer network, no Byzantine fault tolerance, no
   replication. The chain, mempool and UTXO set live in memory; the dashboard never persists.
8. **Local disk attacker.** Someone who can rewrite the `.bclt` file and the code that loads it can do
   anything; pin `expected_genesis_hash` out-of-band to detect whole-file replacement.
9. **Denial of service.** Request sizes are capped, but there is no rate limiting. `?full=1` /
   `{"full": true}` trigger O(n) validation on demand.

## Dependencies

The package has no runtime dependencies (enforced by an AST import audit). `hashlib` is allowed only in
the opt-in `crypto/fast_hash.py`. CI-only tools (ruff, mypy, coverage) are pinned and never imported
by the package.
