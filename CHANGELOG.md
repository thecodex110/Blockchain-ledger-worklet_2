# Changelog

## [1.0.0] - 2026-10-15 — audit remediation

Protocol version stays `1` (no wire-format change). Chains that relied on the old, unenforced
rules are no longer valid (see "Consensus").

### Consensus & security (breaking for invalid chains)
- **D1** Difficulty is enforced from chain history (`ledger/consensus.py`). Fork choice uses
  schedule-verified cumulative work; equal work keeps the active chain. `calculate_next_difficulty`
  is now a pure query, and consensus parameters cannot change after genesis.
- **D2** `ChainPersistence` validates with caller-supplied (or default) protocol parameters and
  rejects files whose header difficulty/reward disagree. New `params=` arguments.
- **D3** Each non-genesis coinbase commits the block height in its `timestamp` field; enforced.
- **D8** Block timestamps: ≥ median of the previous 11 blocks, ≤ now + 2 h. Mempool rejects
  transactions more than 2 h in the future.
- **D5** Dashboard POSTs need a per-run `X-API-Token` and `Content-Type: application/json`; the
  CORS wildcard is gone; a warning is shown when binding to a non-loopback host.
- **D6** Dashboard: threaded server, Content-Length validation, 64 KiB body cap, generic 500s.
- RPC `mine_block` requires a configured `mine_token`; client-supplied timestamps need
  `allow_client_timestamp=True`.

### Fixed
- **D4** Dashboard `/api/merkle_proof` works and verifies against the block header's root.
- **D11** Missing `Dict`/`Optional` imports (validator, merkle, bundler); duplicate
  `RSAPublicKey.bit_length`; `assert` in `send_funds` replaced by `NetworkRPCError`; swallowed
  exception in history indexing; `__version__` now single-sourced (`1.0.0`).
- Benchmark CLI crashed on Windows cp1252 consoles.

### Performance
- **D7** Chain health cached per tip (`validate_full_chain(force=False)`); no dispatcher-wide
  lock; nonce search runs outside the ledger state lock, so reads stay responsive while mining.
- **D9** Incremental mempool validation (one signature check per submission), `max_mempool_size`,
  optional `min_fee`.
- One-pass `failed_block_index` in `FullChainValidator.validate_chain`.
- **D10** Optional `HashlibSHA256` backend (`--fast-hash`), bit-identical to `BitLevelSHA256`;
  about 650x faster hashing on the reference machine.
- `BlockchainLedger.get_block(index)` avoids copying the chain.

### Added
- Anchored SPV: `get_headers` RPC, `BlockHeader`, `WalletClient.fetch_verified_headers`,
  `verify_transaction_inclusion_spv(..., trusted_genesis_hash=, params=)`.
- `--rsa-bits` for the demo and dashboard, with a weak-key warning below 2048 bits.
- Dashboard UX: no `alert()` popups, responsive layout down to 375 px, ARIA tabs and dialog, focus
  management, escaped rendering, polling that pauses when the tab is hidden.
- Tests: attack scenarios (D1–D8), core engineering, dashboard markup, fast hash, serialization
  properties and mutations, SPV and key sizes. 48 → 111 tests.
- Tooling: coverage gate (86% line+branch), ruff, mypy, pinned CI actions, `.dockerignore`,
  HEALTHCHECK, compose `test-suite` service, stdlib logging.
- `SECURITY.md`, `docs/RPC_Reference.md`, this changelog.

### Removed
- `_DirectStatPathFinder` import hook (environment-specific FUSE workaround); `tests/` is now a
  regular package and `python -m unittest discover` works.
- Committed `__pycache__`, empty `scratch/`, stale `blockchain_lite_project_repo.zip`, and the
  duplicate root `Blockchain_Lite_HLD_and_Viva_Guide.md` (merged into `docs/`).
- The 1.4 MB download-hub HTML is no longer embedded in `blockchain_lite_complete.py`.
