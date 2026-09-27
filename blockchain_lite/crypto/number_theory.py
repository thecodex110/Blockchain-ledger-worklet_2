"""
Discrete Structures & Number Theory Core (Worklet 1.1 & 1.2).

Satisfies:
- Worklet 1.1: "Implement modular arithmetic and fast modular exponentiation."
- Worklet 1.2: "Implement Miller–Rabin primality, generate large primes..."
- Learning-outcome check 1: "Why is modular exponentiation cheap but the
  discrete-log / factoring problem hard?"
- Pitfall 1: "Rolling your own modular exponentiation but leaving it slow or
  wrong for large exponents — test it against known values first."
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Tuple

from blockchain_lite.interfaces import CryptoError

# First 168 primes (< 1000) used as a fast trial-division filter before
# running expensive Miller-Rabin modular exponentiation rounds.
SMALL_PRIMES: Tuple[int, ...] = (
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
    239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
    331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
    421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
    509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
    613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
    709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
    821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
    919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997,
)


def _validate_int_operand(val: int, name: str) -> None:
    if isinstance(val, bool) or not isinstance(val, int):
        raise CryptoError(f"{name} must be an integer, got {type(val).__name__}")


def _validate_modulus(modulus: int) -> None:
    if isinstance(modulus, bool) or not isinstance(modulus, int) or modulus <= 0:
        raise CryptoError(f"Modulus must be a positive integer, got {modulus!r}")


def mod_add(a: int, b: int, modulus: int) -> int:
    """Compute (a + b) mod modulus with canonical non-negative remainder in [0, modulus - 1]."""
    _validate_int_operand(a, "a")
    _validate_int_operand(b, "b")
    _validate_modulus(modulus)
    return ((a % modulus) + (b % modulus)) % modulus


def mod_sub(a: int, b: int, modulus: int) -> int:
    """Compute (a - b) mod modulus with canonical non-negative remainder in [0, modulus - 1]."""
    _validate_int_operand(a, "a")
    _validate_int_operand(b, "b")
    _validate_modulus(modulus)
    return ((a % modulus) - (b % modulus) + modulus) % modulus


def mod_mul(a: int, b: int, modulus: int) -> int:
    """Compute (a * b) mod modulus with canonical non-negative remainder in [0, modulus - 1]."""
    _validate_int_operand(a, "a")
    _validate_int_operand(b, "b")
    _validate_modulus(modulus)
    return ((a % modulus) * (b % modulus)) % modulus


@dataclass(frozen=True)
class ModExpTrace:
    """
    Viva Learning-Outcome Check 1 Evidence:
    Records the exact number of modular squarings and modular multiplications
    performed during binary square-and-multiply modular exponentiation.
    """
    result: int
    exponent_bit_length: int
    squarings: int
    multiplications: int

    @property
    def total_modular_ops(self) -> int:
        return self.squarings + self.multiplications


def pow_mod_with_trace(base: int, exponent: int, modulus: int) -> ModExpTrace:
    """
    Fast Modular Exponentiation via Right-to-Left Binary Square-and-Multiply,
    returning both the result and the operation count trace.
    """
    _validate_int_operand(base, "base")
    _validate_modulus(modulus)
    if isinstance(exponent, bool) or not isinstance(exponent, int) or exponent < 0:
        raise CryptoError(f"Exponent must be a non-negative integer, got {exponent!r}")

    if modulus == 1:
        return ModExpTrace(result=0, exponent_bit_length=exponent.bit_length(), squarings=0, multiplications=0)

    result = 1
    current_base = base % modulus
    exp = exponent
    bit_len = exp.bit_length()
    squarings = 0
    multiplications = 0

    while exp > 0:
        if (exp & 1) == 1:
            result = (result * current_base) % modulus
            multiplications += 1
        exp >>= 1
        if exp > 0:
            current_base = (current_base * current_base) % modulus
            squarings += 1

    return ModExpTrace(
        result=result,
        exponent_bit_length=bit_len,
        squarings=squarings,
        multiplications=multiplications,
    )


def pow_mod(base: int, exponent: int, modulus: int) -> int:
    """Compute (base ^ exponent) mod modulus in O(log2(exponent)) steps."""
    return pow_mod_with_trace(base, exponent, modulus).result


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Iterative Extended Euclidean Algorithm.
    Returns `(g, x, y)` such that `a * x + b * y == g == gcd(a, b)` with `g >= 0`.
    """
    _validate_int_operand(a, "a")
    _validate_int_operand(b, "b")

    old_r, r = abs(a), abs(b)
    old_s, s = (1 if a >= 0 else -1), 0
    old_t, t = 0, (1 if b >= 0 else -1)

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    return old_r, old_s, old_t


def gcd(a: int, b: int) -> int:
    """Compute greatest common divisor gcd(a, b) >= 0."""
    g, _, _ = extended_gcd(a, b)
    return g


def lcm(a: int, b: int) -> int:
    """Compute least common multiple lcm(a, b)."""
    _validate_int_operand(a, "a")
    _validate_int_operand(b, "b")
    if a == 0 or b == 0:
        return 0
    return abs(a * b) // gcd(a, b)


def mod_inverse(a: int, modulus: int) -> int:
    """
    Compute the modular multiplicative inverse `x` in [1, modulus - 1] such that
    `(a * x) % modulus == 1`.
    """
    _validate_int_operand(a, "a")
    _validate_modulus(modulus)
    if modulus == 1:
        raise CryptoError("Modular inverse does not exist modulo 1")
    a_mod = a % modulus
    g, x, _ = extended_gcd(a_mod, modulus)
    if g != 1:
        raise CryptoError(
            f"Modular inverse does not exist: gcd({a}, {modulus}) = {g} != 1"
        )
    return x % modulus


def random_bytes_csprng(num_bytes: int) -> bytes:
    """Read cryptographically strong random bytes from the OS entropy source."""
    return os.urandom(num_bytes)


def random_int_in_range(
    low: int,
    high: int,
    rand_bytes_fn: Callable[[int], bytes] = random_bytes_csprng,
) -> int:
    """Generate an unbiased random integer uniformly in `[low, high]`."""
    _validate_int_operand(low, "low")
    _validate_int_operand(high, "high")
    if low > high:
        raise CryptoError(f"Invalid range [{low}, {high}]")
    if low == high:
        return low

    span = high - low
    bit_len = span.bit_length()
    byte_len = (bit_len + 7) // 8
    mask = (1 << bit_len) - 1

    while True:
        candidate = int.from_bytes(rand_bytes_fn(byte_len), byteorder="big") & mask
        if candidate <= span:
            return low + candidate


def is_probable_prime_miller_rabin(
    n: int,
    rounds: int = 40,
    rand_bytes_fn: Callable[[int], bytes] = random_bytes_csprng,
) -> bool:
    """Worklet 1.2: Miller–Rabin Probabilistic Primality Test."""
    if isinstance(n, bool) or not isinstance(n, int):
        raise CryptoError(f"Miller-Rabin requires an integer, got {type(n).__name__}")
    if isinstance(rounds, bool) or not isinstance(rounds, int) or rounds < 1:
        raise CryptoError(f"rounds must be an integer >= 1, got {rounds!r}")

    if n < 2:
        return False
    if n in (2, 3):
        return True
    if (n & 1) == 0:
        return False

    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    d = n - 1
    s = 0
    while (d & 1) == 0:
        d >>= 1
        s += 1

    for _ in range(rounds):
        a = random_int_in_range(2, n - 2, rand_bytes_fn=rand_bytes_fn)
        x = pow_mod(a, d, n)
        if x == 1 or x == n - 1:
            continue

        witnessed_minus_one = False
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                witnessed_minus_one = True
                break
            if x == 1:
                return False

        if not witnessed_minus_one:
            return False

    return True


def generate_large_prime(
    bit_length: int = 256,
    rounds: int = 40,
    rand_bytes_fn: Callable[[int], bytes] = random_bytes_csprng,
) -> int:
    """Generate a random probable prime of exact `bit_length` bits."""
    if isinstance(bit_length, bool) or not isinstance(bit_length, int) or bit_length < 16:
        raise CryptoError(f"bit_length must be an integer >= 16, got {bit_length!r}")

    byte_len = (bit_length + 7) // 8
    top_bit_mask = (1 << (bit_length - 1)) | (1 << (bit_length - 2))
    max_bit_mask = (1 << bit_length) - 1

    while True:
        raw = int.from_bytes(rand_bytes_fn(byte_len), byteorder="big")
        candidate = (raw & max_bit_mask) | top_bit_mask | 1

        divisible_by_small = False
        for p in SMALL_PRIMES:
            if candidate % p == 0 and candidate != p:
                divisible_by_small = True
                break
        if divisible_by_small:
            continue

        if is_probable_prime_miller_rabin(candidate, rounds=rounds, rand_bytes_fn=rand_bytes_fn):
            return candidate
