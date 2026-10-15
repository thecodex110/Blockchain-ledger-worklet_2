"""
Bit-Level Cryptographic Hash Engine (FIPS 180-4 SHA-256 From Scratch).

Satisfies:
- Foundational courses: "Digital Logic & Computer Organization (the bit-level behaviour of hashing)"
- Worklet 2.4: "Implement a hash interface; explain the bit-level behaviour that makes it tamper-evident."
- Exclusions: Built purely from 32-bit bitwise logic operations (XOR, AND, NOT, right-rotate,
  right-shift, and modulo-2^32 adder arithmetic) without OpenSSL or external crypto libraries.

Bit-Level DLCO Principles Demonstrated:
1. 32-bit Register Masking (`MASK32 = 0xFFFFFFFF`): Simulates hardware 32-bit ALU registers
   where arithmetic addition wraps modulo 2^32 (discarding carry-out bit 32).
2. Non-Linear Bit Mixing (`Ch` and `Maj` gates):
   - Choice (`Ch(x, y, z) = (x & y) ^ (~x & z)`): Bitwise multiplexer where bit `x_i` selects `y_i` or `z_i`.
   - Majority (`Maj(x, y, z) = (x & y) ^ (x & z) ^ (y & z)`): Hardware majority voting gate per bit position.
   - Because `Ch` and `Maj` are non-linear over GF(2), an attacker cannot solve a system of linear
     equations (Gaussian elimination) to invert the hash or forge a preimage.
3. Bitwise Rotational Diffusion (`Sigma0`, `Sigma1`, `sigma0`, `sigma1`):
   - Circular right rotations (`ROTR`) and logical right shifts (`SHR`) spread a single flipped bit
     across multiple bit positions within a single 32-bit word.
   - Combined with modulo-2^32 carry propagation across 64 compression rounds, flipping 1 input bit
     cascades into flipping ~50% of the 256 output bits (the Strict Avalanche Criterion).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from blockchain_lite.interfaces import (
    HASH_DIGEST_SIZE,
    AvalancheReport,
    HashInterface,
)

# 32-bit ALU register bitmask (2^32 - 1)
MASK32: int = 0xFFFFFFFF

# Initial Hash Values H^(0): first 32 bits of the fractional parts of the
# square roots of the first 8 primes (2, 3, 5, 7, 11, 13, 17, 19).
INITIAL_STATE: Tuple[int, ...] = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

# Round Constants K_0 .. K_63: first 32 bits of the fractional parts of the
# cube roots of the first 64 primes (2 .. 311).
ROUND_CONSTANTS: Tuple[int, ...] = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


# ============================================================================
# Elementary 32-Bit Digital Logic Gates & ALU Operations
# ============================================================================

def rotr32(x: int, n: int) -> int:
    """Circular right rotate of a 32-bit word `x` by `n` bit positions."""
    x &= MASK32
    return ((x >> n) | (x << (32 - n))) & MASK32


def shr32(x: int, n: int) -> int:
    """Logical right shift of a 32-bit word `x` by `n` bit positions (fills with 0s)."""
    return (x & MASK32) >> n


def add32(*words: int) -> int:
    """Modulo 2^32 unsigned addition across 32-bit ALU registers."""
    total = 0
    for w in words:
        total = (total + w) & MASK32
    return total


def ch_gate(x: int, y: int, z: int) -> int:
    """
    Bitwise Choice (2-to-1 Multiplexer per bit):
    If bit i of x is 1, choose bit i of y; else choose bit i of z.
    """
    return ((x & y) ^ ((~x & MASK32) & z)) & MASK32


def maj_gate(x: int, y: int, z: int) -> int:
    """
    Bitwise Majority Gate:
    Output bit i is 1 if and only if at least two of (x_i, y_i, z_i) are 1.
    """
    return ((x & y) ^ (x & z) ^ (y & z)) & MASK32


def big_sigma0(x: int) -> int:
    """Compression diffusion function Sigma_0(x) = ROTR^2(x) ^ ROTR^13(x) ^ ROTR^22(x)."""
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22)


def big_sigma1(x: int) -> int:
    """Compression diffusion function Sigma_1(x) = ROTR^6(x) ^ ROTR^11(x) ^ ROTR^25(x)."""
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25)


def small_sigma0(x: int) -> int:
    """Message schedule diffusion sigma_0(x) = ROTR^7(x) ^ ROTR^18(x) ^ SHR^3(x)."""
    return rotr32(x, 7) ^ rotr32(x, 18) ^ shr32(x, 3)


def small_sigma1(x: int) -> int:
    """Message schedule diffusion sigma_1(x) = ROTR^17(x) ^ ROTR^19(x) ^ SHR^10(x)."""
    return rotr32(x, 17) ^ rotr32(x, 19) ^ shr32(x, 10)


@dataclass(frozen=True)
class RoundStateSnapshot:
    """Captures the 8 working 32-bit registers (a..h) after a compression round."""
    round_index: int
    registers: Tuple[int, int, int, int, int, int, int, int]


# ============================================================================
# SHA-256 Implementation (HashInterface)
# ============================================================================

class BitLevelSHA256(HashInterface):
    """
    Pure, bit-level implementation of SHA-256 (FIPS 180-4) with round-by-round
    register tracing and avalanche analysis for viva demonstration.
    """

    @property
    def digest_size(self) -> int:
        return HASH_DIGEST_SIZE

    @staticmethod
    def pad_message(data: bytes) -> bytes:
        """
        Merkle-Damgard Strengthening / FIPS 180-4 Padding:
        1. Append single '1' bit (`0x80` byte).
        2. Append '0' bytes until length in bytes is congruent to 56 (mod 64)
           [i.e., 448 bits (mod 512)].
        3. Append the original message length in bits as a 64-bit big-endian integer.
        This guarantees that messages of different lengths can never share the same
        padded block suffix, thwarting trivial length-ambiguity collisions.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError(f"Expected bytes-like object, got {type(data).__name__}")

        msg_byte_len = len(data)
        msg_bit_len = msg_byte_len * 8

        padded = bytearray(data)
        padded.append(0x80)  # Append bit '1' followed by seven '0' bits

        while (len(padded) % 64) != 56:
            padded.append(0x00)

        # Append 64-bit big-endian bit-length
        padded.extend(msg_bit_len.to_bytes(8, byteorder="big", signed=False))
        return bytes(padded)

    @staticmethod
    def _expand_message_schedule(chunk64: bytes) -> List[int]:
        """Expand a 64-byte (512-bit) block into sixty-four 32-bit words W[0..63]."""
        w: List[int] = [0] * 64
        for i in range(16):
            offset = i * 4
            w[i] = int.from_bytes(chunk64[offset : offset + 4], byteorder="big")
        for i in range(16, 64):
            w[i] = add32(
                small_sigma1(w[i - 2]),
                w[i - 7],
                small_sigma0(w[i - 15]),
                w[i - 16],
            )
        return w

    def compress_chunk_with_trace(
        self, chunk64: bytes, state: Tuple[int, ...] = INITIAL_STATE
    ) -> Tuple[Tuple[int, ...], List[RoundStateSnapshot]]:
        """
        Execute the 64-round Davies-Meyer compression function on a 512-bit chunk,
        returning both the updated 8-word state and the round-by-round register snapshots.
        """
        if len(chunk64) != 64:
            raise ValueError(f"Chunk must be exactly 64 bytes, got {len(chunk64)}")

        w = self._expand_message_schedule(chunk64)
        a, b, c, d, e, f, g, h = state
        snapshots: List[RoundStateSnapshot] = []

        for t in range(64):
            t1 = add32(h, big_sigma1(e), ch_gate(e, f, g), ROUND_CONSTANTS[t], w[t])
            t2 = add32(big_sigma0(a), maj_gate(a, b, c))
            h = g
            g = f
            f = e
            e = add32(d, t1)
            d = c
            c = b
            b = a
            a = add32(t1, t2)
            snapshots.append(RoundStateSnapshot(round_index=t, registers=(a, b, c, d, e, f, g, h)))

        next_state = (
            add32(state[0], a),
            add32(state[1], b),
            add32(state[2], c),
            add32(state[3], d),
            add32(state[4], e),
            add32(state[5], f),
            add32(state[6], g),
            add32(state[7], h),
        )
        return next_state, snapshots

    def hash_bytes(self, data: bytes) -> bytes:
        """Compute the 32-byte SHA-256 digest of `data` using pure bitwise operations."""
        padded = self.pad_message(data)
        state = INITIAL_STATE

        for offset in range(0, len(padded), 64):
            chunk = padded[offset : offset + 64]
            state, _ = self.compress_chunk_with_trace(chunk, state)

        out = bytearray(32)
        for idx, word in enumerate(state):
            out[idx * 4 : (idx + 1) * 4] = word.to_bytes(4, byteorder="big", signed=False)
        return bytes(out)

    def hash_hex(self, data: bytes) -> str:
        """Compute the 64-character lowercase hex SHA-256 digest of `data`."""
        return self.hash_bytes(data).hex()

    @staticmethod
    def hamming_distance_bits(bytes_a: bytes, bytes_b: bytes) -> int:
        """
        Compute the exact number of differing bits between two byte sequences.
        If lengths differ, each missing byte counts as 8 differing bits.
        """
        min_len = min(len(bytes_a), len(bytes_b))
        diff_bits = abs(len(bytes_a) - len(bytes_b)) * 8
        for i in range(min_len):
            xor_byte = bytes_a[i] ^ bytes_b[i]
            diff_bits += xor_byte.bit_count()
        return diff_bits

    def analyze_avalanche(self, original: bytes, modified: bytes) -> AvalancheReport:
        """
        Compare two inputs and their 256-bit digests at the bit and byte level
        to demonstrate the Strict Avalanche Criterion (~50% output bits flip on a 1-bit change).
        """
        digest_orig = self.hash_bytes(original)
        digest_mod = self.hash_bytes(modified)

        in_flipped = self.hamming_distance_bits(original, modified)
        out_flipped = self.hamming_distance_bits(digest_orig, digest_mod)
        total_bits = self.digest_size * 8

        diff_indices = tuple(
            i for i in range(self.digest_size) if digest_orig[i] != digest_mod[i]
        )

        return AvalancheReport(
            original_input=bytes(original),
            modified_input=bytes(modified),
            original_digest_hex=digest_orig.hex(),
            modified_digest_hex=digest_mod.hex(),
            input_bits_flipped=in_flipped,
            output_bits_flipped=out_flipped,
            total_output_bits=total_bits,
            flip_ratio=out_flipped / total_bits,
            differing_byte_indices=diff_indices,
        )


# Default singleton instance shared across Worklets 1, 2, and 3
default_hasher = BitLevelSHA256()
