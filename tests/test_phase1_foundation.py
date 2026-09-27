"""
Phase 1 Automated Verification Suite:
- Cross-Worklet Interfaces & Constants (`blockchain_lite/interfaces.py`)
- Canonical ByteBuffer Serialization (`blockchain_lite/serialization.py`)
- Bit-Level SHA-256 Hash Engine & DLCO Avalanche Analysis (`blockchain_lite/crypto/hashing.py`)
- Static Exclusion Audit across ALL package modules (verifying zero forbidden imports/libraries)
"""

from __future__ import annotations

import ast
import pathlib
import unittest

from blockchain_lite.crypto.hashing import (
    INITIAL_STATE,
    BitLevelSHA256,
    add32,
    ch_gate,
    default_hasher,
    maj_gate,
    rotr32,
    shr32,
)
from blockchain_lite.interfaces import (
    MAX_UINT8,
    MAX_UINT32,
    MAX_UINT64,
    SerializationError,
)
from blockchain_lite.serialization import ByteBuffer


class TestBitLevelSHA256(unittest.TestCase):
    """Verify the from-scratch SHA-256 engine against official NIST FIPS 180-4 test vectors."""

    def setUp(self) -> None:
        self.hasher = BitLevelSHA256()

    def test_elementary_32bit_logic_gates(self) -> None:
        self.assertEqual(add32(0xFFFFFFFF, 1), 0x00000000)
        self.assertEqual(add32(0xFFFFFFFF, 2), 0x00000001)

        word = 0x80000001
        self.assertEqual(rotr32(word, 1), 0xC0000000)
        self.assertEqual(shr32(word, 1), 0x40000000)

        self.assertEqual(ch_gate(0xFFFFFFFF, 0xAAAAAAAA, 0x55555555), 0xAAAAAAAA)
        self.assertEqual(ch_gate(0x00000000, 0xAAAAAAAA, 0x55555555), 0x55555555)

        self.assertEqual(maj_gate(0b1100, 0b1010, 0b1001), 0b1000)

    def test_nist_fips_180_4_standard_vectors(self) -> None:
        self.assertEqual(
            self.hasher.hash_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        self.assertEqual(
            self.hasher.hash_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        msg_56 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        self.assertEqual(
            self.hasher.hash_hex(msg_56),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        )
        self.assertEqual(
            self.hasher.hash_hex(b"The quick brown fox jumps over the lazy dog"),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        )

    def test_merkle_damgard_padding_invariants(self) -> None:
        for length in [0, 1, 55, 56, 57, 63, 64, 128, 250]:
            raw = bytes([i % 256 for i in range(length)])
            padded = self.hasher.pad_message(raw)
            self.assertEqual(len(padded) % 64, 0)
            self.assertGreaterEqual(len(padded), length + 9)
            encoded_bits = int.from_bytes(padded[-8:], byteorder="big")
            self.assertEqual(encoded_bits, length * 8)

    def test_avalanche_effect_single_bit_flip(self) -> None:
        orig = b"Alice pays Bob 100 academic tokens in Transaction #0001"
        mod = bytearray(orig)
        mod[-1] ^= 0x01

        report = self.hasher.analyze_avalanche(orig, bytes(mod))
        self.assertEqual(report.input_bits_flipped, 1)
        self.assertEqual(report.total_output_bits, 256)
        self.assertGreaterEqual(report.output_bits_flipped, 90)
        self.assertLessEqual(report.output_bits_flipped, 166)
        self.assertGreater(len(report.differing_byte_indices), 24)

    def test_round_by_round_compression_trace(self) -> None:
        padded = self.hasher.pad_message(b"trace-test")
        final_state, snapshots = self.hasher.compress_chunk_with_trace(
            padded[:64], INITIAL_STATE
        )
        self.assertEqual(len(snapshots), 64)
        self.assertEqual(snapshots[0].round_index, 0)
        self.assertEqual(snapshots[63].round_index, 63)
        self.assertEqual(len(final_state), 8)


class TestCanonicalByteBuffer(unittest.TestCase):
    """Verify deterministic big-endian serialization and strict validation rules."""

    def test_primitive_round_trip(self) -> None:
        digest = default_hasher.hash_bytes(b"sample-tx")
        big_modulus = (1 << 512) + 65537

        writer = ByteBuffer()
        writer.write_uint8(0)
        writer.write_uint8(MAX_UINT8)
        writer.write_uint32(42)
        writer.write_uint32(MAX_UINT32)
        writer.write_uint64(100_000_000)
        writer.write_uint64(MAX_UINT64)
        writer.write_hash32(digest)
        writer.write_var_bytes(b"\x01\x02\x03\x04")
        writer.write_utf8("COEP-Mini-Project-5")
        writer.write_bigint(0)
        writer.write_bigint(big_modulus)

        raw = writer.to_bytes()
        reader = ByteBuffer(raw)

        self.assertEqual(reader.read_uint8(), 0)
        self.assertEqual(reader.read_uint8(), MAX_UINT8)
        self.assertEqual(reader.read_uint32(), 42)
        self.assertEqual(reader.read_uint32(), MAX_UINT32)
        self.assertEqual(reader.read_uint64(), 100_000_000)
        self.assertEqual(reader.read_uint64(), MAX_UINT64)
        self.assertEqual(reader.read_hash32(), digest)
        self.assertEqual(reader.read_var_bytes(), b"\x01\x02\x03\x04")
        self.assertEqual(reader.read_utf8(), "COEP-Mini-Project-5")
        self.assertEqual(reader.read_bigint(), 0)
        self.assertEqual(reader.read_bigint(), big_modulus)
        reader.assert_exhausted()

    def test_rejects_out_of_range_and_non_integer_types(self) -> None:
        buf = ByteBuffer()
        with self.assertRaises(SerializationError):
            buf.write_uint8(-1)
        with self.assertRaises(SerializationError):
            buf.write_uint8(256)
        with self.assertRaises(SerializationError):
            buf.write_uint32(MAX_UINT32 + 1)
        with self.assertRaises(SerializationError):
            buf.write_uint64(-50)
        with self.assertRaises(SerializationError):
            buf.write_uint64(True)
        with self.assertRaises(SerializationError):
            buf.write_uint64(12.34)  # type: ignore[arg-type]

    def test_rejects_underflow_and_trailing_bytes(self) -> None:
        buf = ByteBuffer()
        buf.write_uint32(12345)
        buf.write_uint8(99)

        reader = ByteBuffer(buf.to_bytes())
        self.assertEqual(reader.read_uint32(), 12345)
        with self.assertRaises(SerializationError):
            reader.assert_exhausted()
        self.assertEqual(reader.read_uint8(), 99)
        reader.assert_exhausted()

        with self.assertRaises(SerializationError):
            reader.read_uint8()

    def test_rejects_non_canonical_bigint_leading_zeros(self) -> None:
        malformed = ByteBuffer()
        malformed.write_var_bytes(b"\x00\x05")

        reader = ByteBuffer(malformed.to_bytes())
        with self.assertRaises(SerializationError):
            reader.read_bigint()


class TestExclusionsCompliance(unittest.TestCase):
    """
    Verify CON-001 across every module in `blockchain_lite/` (one documented exception below):
    Ensure zero prohibited libraries (`hashlib`, `cryptography`, `OpenSSL`,
    `sqlite3`, `sqlalchemy`, `flask`, `fastapi`, `django`, `web3`, `bitcoin`,
    `torch`, `sklearn`) are imported anywhere.
    """

    FORBIDDEN_MODULES = {
        "hashlib",
        "hmac",
        "cryptography",
        "OpenSSL",
        "nacl",
        "Crypto",
        "Cryptodome",
        "ecdsa",
        "rsa",
        "sqlite3",
        "sqlalchemy",
        "peewee",
        "pymongo",
        "psycopg2",
        "flask",
        "fastapi",
        "django",
        "tornado",
        "aiohttp",
        "requests",
        "web3",
        "bitcoin",
        "eth_account",
        "sklearn",
        "torch",
        "tensorflow",
    }

    PACKAGE_MODULES = [
        "blockchain_lite/__init__.py",
        "blockchain_lite/interfaces.py",
        "blockchain_lite/serialization.py",
        "blockchain_lite/crypto/__init__.py",
        "blockchain_lite/crypto/hashing.py",
        "blockchain_lite/crypto/number_theory.py",
        "blockchain_lite/crypto/asymmetric.py",
        "blockchain_lite/crypto/fast_hash.py",
        "blockchain_lite/models/__init__.py",
        "blockchain_lite/models/transaction.py",
        "blockchain_lite/models/block.py",
        "blockchain_lite/wallet/__init__.py",
        "blockchain_lite/wallet/wallet.py",
        "blockchain_lite/ledger/__init__.py",
        "blockchain_lite/ledger/merkle.py",
        "blockchain_lite/ledger/pow.py",
        "blockchain_lite/ledger/utxo.py",
        "blockchain_lite/ledger/validator.py",
        "blockchain_lite/ledger/chain.py",
        "blockchain_lite/ledger/persistence.py",
        "blockchain_lite/ledger/consensus.py",
        "blockchain_lite/benchmarks/__init__.py",
        "blockchain_lite/benchmarks/pow_benchmark.py",
        "blockchain_lite/network/__init__.py",
        "blockchain_lite/network/transport.py",
        "blockchain_lite/network/server.py",
        "blockchain_lite/network/client.py",
        "blockchain_lite/network/web_dashboard.py",
        "blockchain_lite/wallet/demo_wallets.py",
        "blockchain_lite/cli/__init__.py",
        "blockchain_lite/cli/demo.py",
        "blockchain_lite/cli/terminal.py",
    ]

    # The single documented exception. `crypto/fast_hash.py` is an OPT-IN backend
    # (`--fast-hash`) that wraps hashlib.sha256 for server throughput; the from-scratch
    # `BitLevelSHA256` stays the default and is what the educational path uses. Digest
    # equivalence is proven in tests/test_phase11_fast_hash.py. Nothing else is exempt.
    ALLOWED_EXCEPTIONS = {
        "blockchain_lite/crypto/fast_hash.py": {"hashlib"},
    }

    def test_zero_prohibited_imports_in_package(self) -> None:
        repo_root = pathlib.Path(__file__).resolve().parent.parent
        for rel_path in self.PACKAGE_MODULES:
            self.assertTrue((repo_root / rel_path).is_file(), f"Expected module missing: {rel_path}")

        # Audit EVERY module in the package, so new files are covered automatically.
        all_modules = sorted(
            p.relative_to(repo_root).as_posix() for p in (repo_root / "blockchain_lite").rglob("*.py")
        )
        for rel_path in all_modules:
            forbidden = self.FORBIDDEN_MODULES - self.ALLOWED_EXCEPTIONS.get(rel_path, set())
            tree = ast.parse((repo_root / rel_path).read_text(encoding="utf-8"), filename=rel_path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top_mod = alias.name.split(".")[0]
                        self.assertNotIn(
                            top_mod,
                            forbidden,
                            f"Forbidden import '{alias.name}' found in {rel_path}",
                        )
                elif isinstance(node, ast.ImportFrom) and node.module:
                    top_mod = node.module.split(".")[0]
                    self.assertNotIn(
                        top_mod,
                        forbidden,
                        f"Forbidden import from '{node.module}' found in {rel_path}",
                    )

    def test_exception_list_is_exactly_fast_hash(self) -> None:
        self.assertEqual(self.ALLOWED_EXCEPTIONS, {"blockchain_lite/crypto/fast_hash.py": {"hashlib"}})


if __name__ == "__main__":
    unittest.main()
