"""
Canonical Byte-Buffer Serialization Engine (`ByteBuffer`).

Satisfies:
- Data structures: "Byte buffers for serialization"
- Worklet 1.4: "serialize canonically"
- Worklet 3.4: "Persist the chain and reload it, re-validating; add integrity checks"
- Exclusions: Zero use of databases, ORMs, or floating-point numbers; deterministic
  big-endian binary encoding with strict bounds and cursor checks.
"""

from __future__ import annotations

import struct

from blockchain_lite.interfaces import (
    HASH_DIGEST_SIZE,
    MAX_UINT8,
    MAX_UINT32,
    MAX_UINT64,
    SerializationError,
)


class ByteBuffer:
    """
    A deterministic, cursor-tracked binary buffer for canonical serialization
    and deserialization across Worklets 1, 2, and 3.

    Wire Format Conventions:
    - All multi-byte integers are encoded in Unsigned Big-Endian (network byte order).
    - Floating-point numbers are strictly prohibited to prevent precision loss and
      non-canonical NaN/endianness discrepancies.
    - Variable-length byte sequences are length-prefixed with a 4-byte `uint32`.
    - Fixed-width digests (hashes/addresses) are written as exact 32-byte slices.
    """

    def __init__(self, initial_bytes: bytes = b"") -> None:
        if not isinstance(initial_bytes, (bytes, bytearray, memoryview)):
            raise SerializationError(
                f"ByteBuffer requires bytes-like object, got {type(initial_bytes).__name__}"
            )
        self._buffer: bytearray = bytearray(initial_bytes)
        self._offset: int = 0

    # ------------------------------------------------------------------------
    # Buffer State & Navigation
    # ------------------------------------------------------------------------

    @property
    def offset(self) -> int:
        """Current read cursor offset in bytes."""
        return self._offset

    @property
    def remaining(self) -> int:
        """Number of unread bytes remaining from the current cursor offset."""
        return len(self._buffer) - self._offset

    def __len__(self) -> int:
        return len(self._buffer)

    def to_bytes(self) -> bytes:
        """Return an immutable `bytes` snapshot of the entire buffer."""
        return bytes(self._buffer)

    def assert_exhausted(self) -> None:
        """
        Verify that no trailing unparsed bytes remain in the buffer.
        Essential for preventing canonical malleability (e.g. appended junk bytes).
        """
        if self.remaining != 0:
            raise SerializationError(
                f"Non-canonical trailing bytes detected: {self.remaining} unparsed byte(s) remain"
            )

    # ------------------------------------------------------------------------
    # Canonical Write Primitives (Big-Endian)
    # ------------------------------------------------------------------------

    def write_uint8(self, value: int) -> "ByteBuffer":
        """Write an unsigned 8-bit integer (1 byte, big-endian)."""
        self._validate_int(value, 0, MAX_UINT8, "uint8")
        self._buffer.append(value)
        return self

    def write_uint32(self, value: int) -> "ByteBuffer":
        """Write an unsigned 32-bit integer (4 bytes, big-endian)."""
        self._validate_int(value, 0, MAX_UINT32, "uint32")
        self._buffer.extend(struct.pack(">I", value))
        return self

    def write_uint64(self, value: int) -> "ByteBuffer":
        """Write an unsigned 64-bit integer (8 bytes, big-endian)."""
        self._validate_int(value, 0, MAX_UINT64, "uint64")
        self._buffer.extend(struct.pack(">Q", value))
        return self

    def write_fixed_bytes(self, data: bytes, expected_length: int) -> "ByteBuffer":
        """Write a fixed-length byte sequence (e.g., 32-byte hash digest)."""
        if not isinstance(data, (bytes, bytearray)):
            raise SerializationError(
                f"Expected bytes for fixed field, got {type(data).__name__}"
            )
        if len(data) != expected_length:
            raise SerializationError(
                f"Fixed-length byte field requires exactly {expected_length} bytes, got {len(data)}"
            )
        self._buffer.extend(data)
        return self

    def write_hash32(self, digest: bytes) -> "ByteBuffer":
        """Write an exact 32-byte cryptographic digest or address."""
        return self.write_fixed_bytes(digest, HASH_DIGEST_SIZE)

    def write_var_bytes(self, data: bytes) -> "ByteBuffer":
        """Write a variable-length byte array prefixed by its 4-byte `uint32` length."""
        if not isinstance(data, (bytes, bytearray)):
            raise SerializationError(
                f"Expected bytes for variable field, got {type(data).__name__}"
            )
        self.write_uint32(len(data))
        self._buffer.extend(data)
        return self

    def write_utf8(self, text: str) -> "ByteBuffer":
        """Write a UTF-8 string as length-prefixed canonical bytes."""
        if not isinstance(text, str):
            raise SerializationError(f"Expected str, got {type(text).__name__}")
        encoded = text.encode("utf-8")
        return self.write_var_bytes(encoded)

    def write_bigint(self, value: int) -> "ByteBuffer":
        """
        Write an arbitrary-precision non-negative integer (such as an RSA modulus,
        exponent, or signature integer) canonically as length-prefixed big-endian bytes.
        Zero is canonically encoded as a 1-byte `0x00` payload.
        """
        if isinstance(value, bool) or not isinstance(value, int):
            raise SerializationError(f"BigInt requires int, got {type(value).__name__}")
        if value < 0:
            raise SerializationError("Canonical BigInt must be non-negative")
        if value == 0:
            raw = b"\x00"
        else:
            byte_len = (value.bit_length() + 7) // 8
            raw = value.to_bytes(byte_len, byteorder="big", signed=False)
        return self.write_var_bytes(raw)

    # ------------------------------------------------------------------------
    # Canonical Read Primitives (Big-Endian)
    # ------------------------------------------------------------------------

    def read_uint8(self) -> int:
        """Read an unsigned 8-bit integer (1 byte)."""
        raw = self._read_raw(1)
        return raw[0]

    def read_uint32(self) -> int:
        """Read an unsigned 32-bit integer (4 bytes, big-endian)."""
        raw = self._read_raw(4)
        return struct.unpack(">I", raw)[0]

    def read_uint64(self) -> int:
        """Read an unsigned 64-bit integer (8 bytes, big-endian)."""
        raw = self._read_raw(8)
        return struct.unpack(">Q", raw)[0]

    def read_fixed_bytes(self, expected_length: int) -> bytes:
        """Read an exact number of raw bytes."""
        if expected_length < 0:
            raise SerializationError(f"Invalid negative length: {expected_length}")
        return self._read_raw(expected_length)

    def read_hash32(self) -> bytes:
        """Read an exact 32-byte cryptographic digest or address."""
        return self.read_fixed_bytes(HASH_DIGEST_SIZE)

    def read_var_bytes(self, max_length: int = 10 * 1024 * 1024) -> bytes:
        """Read a `uint32` length-prefixed byte sequence with upper-bound protection."""
        length = self.read_uint32()
        if length > max_length:
            raise SerializationError(
                f"Variable byte field length {length} exceeds maximum allowed {max_length}"
            )
        return self._read_raw(length)

    def read_utf8(self, max_length: int = 1024 * 1024) -> str:
        """Read a length-prefixed UTF-8 string."""
        raw = self.read_var_bytes(max_length=max_length)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SerializationError(f"Invalid UTF-8 byte sequence: {exc}") from exc

    def read_bigint(self, max_byte_length: int = 4096) -> int:
        """
        Read a canonically encoded arbitrary-precision non-negative integer.
        Rejects redundant leading zero bytes (except for the single-byte value `0x00`)
        to guarantee strict 1-to-1 canonical encoding.
        """
        raw = self.read_var_bytes(max_length=max_byte_length)
        if len(raw) == 0:
            raise SerializationError("Empty BigInt encoding is non-canonical")
        if len(raw) > 1 and raw[0] == 0:
            raise SerializationError(
                "Non-canonical leading zero byte in BigInt serialization"
            )
        return int.from_bytes(raw, byteorder="big", signed=False)

    # ------------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------------

    def _read_raw(self, num_bytes: int) -> bytes:
        if self._offset + num_bytes > len(self._buffer):
            raise SerializationError(
                f"Buffer underflow: needed {num_bytes} byte(s) at offset {self._offset}, "
                f"but only {self.remaining} byte(s) available"
            )
        start = self._offset
        end = start + num_bytes
        self._offset = end
        return bytes(self._buffer[start:end])

    @staticmethod
    def _validate_int(value: int, min_val: int, max_val: int, type_name: str) -> None:
        # Note: in Python, `bool` is a subclass of `int`, so explicitly reject `bool`
        if isinstance(value, bool) or not isinstance(value, int):
            raise SerializationError(
                f"{type_name} requires an integer, got {type(value).__name__}"
            )
        if value < min_val or value > max_val:
            raise SerializationError(
                f"{type_name} value {value} out of range [{min_val}, {max_val}]"
            )
