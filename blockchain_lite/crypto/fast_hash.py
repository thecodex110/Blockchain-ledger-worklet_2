"""
Optional fast SHA-256 backend for servers and benchmarks (audit finding D10).

`BitLevelSHA256` (pure Python, from FIPS 180-4) remains `default_hasher` and is what
the educational path and the test-suite exercise. This module wraps the platform's
`hashlib.sha256` and is selected only on request (`--fast-hash`, or `hasher=` on the
ledger / persistence / miner). Digests are bit-identical, so blocks, Merkle roots and
persisted files are byte-identical whichever backend produced or validates them.

Import policy: this is the ONLY package module allowed to import `hashlib`; it is
exempted by name in `TestExclusionsCompliance`, and no other package module imports
it at load time.
"""

from __future__ import annotations

import hashlib

from blockchain_lite.crypto.hashing import BitLevelSHA256


class HashlibSHA256(BitLevelSHA256):
    """Same contract as `BitLevelSHA256`; only `hash_bytes` is delegated to hashlib."""

    def hash_bytes(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()
