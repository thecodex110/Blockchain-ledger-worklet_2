"""
RSA Asymmetric Cryptography Engine (Worklet 1.2 & 1.4).

Cryptographic Specification & Educational Scope Notice:
- Implements a deterministic, domain-separated SHA-256 RSA signature scheme built
  entirely from first principles (`number_theory.py` and `hashing.py`) without OpenSSL.
- This is a custom educational deterministic hash-and-sign construction, NOT
  probabilistic RFC 8017 RSA-PSS:
    `digest = SHA256(b"BCLT-RSA-SHA256-V1|" || public_key_bytes || b"|" || message_bytes)`
    `m_int  = int_from_big_endian(b"\\x01" || digest || b"\\xbc")` (272 bits / 34 bytes)
    `sig    = pow_mod(m_int, d, n)`
- Key Sizes:
  * `MIN_RSA_MODULUS_BITS = 384`: Fast test-fixture floor (strictly exceeds the 272-bit
    message representative).
  * `DEFAULT_RSA_MODULUS_BITS = 512`: Default for interactive classroom demonstrations.
  * `RECOMMENDED_PRODUCTION_RSA_BITS = 2048`: Documented reference constant. 384-bit and
    512-bit RSA moduli are for educational demonstration only and must never be used to
    protect real-world financial assets.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from blockchain_lite.crypto.hashing import default_hasher
from blockchain_lite.crypto.number_theory import (
    gcd,
    generate_large_prime,
    lcm,
    mod_inverse,
    pow_mod,
    random_bytes_csprng,
)
from blockchain_lite.interfaces import (
    AsymmetricCryptoInterface,
    CanonicalSerializable,
    CryptoError,
    HashInterface,
    SerializationError,
)
from blockchain_lite.serialization import ByteBuffer

DEFAULT_RSA_MODULUS_BITS: int = 512
MIN_RSA_MODULUS_BITS: int = 384
RECOMMENDED_PRODUCTION_RSA_BITS: int = 2048


def weak_key_warning(bit_length: int) -> Optional[str]:
    """Banner text for CLIs when `bit_length` is below the 2048-bit reference, else None."""
    if bit_length >= RECOMMENDED_PRODUCTION_RSA_BITS:
        return None
    return (
        f"WARNING: RSA-{bit_length} keys are EDUCATIONAL ONLY and can be factored with modest "
        f"resources. Use --rsa-bits {RECOMMENDED_PRODUCTION_RSA_BITS} (or more) for anything beyond "
        "a classroom demo. Even then, the custom hash-and-sign scheme and non-constant-time "
        "arithmetic are not production cryptography."
    )
RSA_PUBLIC_EXPONENT: int = 65537
SIGNATURE_DOMAIN_TAG: bytes = b"BCLT-RSA-SHA256-V1|"


@dataclass(frozen=True)
class RSAPublicKey(CanonicalSerializable):
    """RSA Public Key `(n, e)`."""
    n: int
    e: int

    def __post_init__(self) -> None:
        if (
            isinstance(self.n, bool)
            or isinstance(self.e, bool)
            or not isinstance(self.n, int)
            or not isinstance(self.e, int)
        ):
            raise CryptoError("RSA public key parameters must be integers")
        if self.n <= 0 or (self.n & 1) == 0 or self.e <= 1 or (self.e & 1) == 0:
            raise CryptoError("Invalid RSA public key parameters (n and e must be positive odd integers)")
        if self.n.bit_length() < MIN_RSA_MODULUS_BITS:
            raise CryptoError(
                f"RSA modulus bit length {self.n.bit_length()} is below minimum {MIN_RSA_MODULUS_BITS} bits"
            )

    @property
    def bit_length(self) -> int:
        return self.n.bit_length()

    def to_bytes(self) -> bytes:
        buf = ByteBuffer()
        buf.write_bigint(self.n)
        buf.write_bigint(self.e)
        return buf.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> "RSAPublicKey":
        try:
            reader = ByteBuffer(data)
            n = reader.read_bigint()
            e = reader.read_bigint()
            reader.assert_exhausted()
            return cls(n=n, e=e)
        except (SerializationError, CryptoError) as exc:
            raise CryptoError(f"Failed to deserialize RSAPublicKey: {exc}") from exc

    def derive_address(self, hasher: HashInterface = default_hasher) -> bytes:
        return hasher.hash_bytes(self.to_bytes())

    @property
    def is_production_grade(self) -> bool:
        return self.bit_length >= RECOMMENDED_PRODUCTION_RSA_BITS

    def format_security_summary(self) -> str:
        status = "PRODUCTION-GRADE" if self.is_production_grade else "EDUCATIONAL-ONLY"
        return (
            f"RSA-{self.bit_length} ({status}): modulus {self.bit_length} bits. "
            f"Recommended minimum for real financial assets is {RECOMMENDED_PRODUCTION_RSA_BITS} bits."
        )


@dataclass(frozen=True)
class RSAPrivateKey(CanonicalSerializable):
    """RSA Private Key `(n, e, d, p, q)`."""
    n: int
    e: int
    d: int
    p: int = 0
    q: int = 0

    def __post_init__(self) -> None:
        for val in (self.n, self.e, self.d, self.p, self.q):
            if isinstance(val, bool) or not isinstance(val, int):
                raise CryptoError("RSA private key parameters must be integers")
        if self.n <= 0 or (self.n & 1) == 0 or self.e <= 1 or (self.e & 1) == 0 or self.d <= 1:
            raise CryptoError("Invalid RSA private key parameters")
        if self.n.bit_length() < MIN_RSA_MODULUS_BITS:
            raise CryptoError(
                f"RSA modulus bit length {self.n.bit_length()} is below minimum {MIN_RSA_MODULUS_BITS} bits"
            )
        if self.p != 0 or self.q != 0:
            if self.p <= 1 or self.q <= 1 or self.p == self.q or (self.p * self.q != self.n):
                raise CryptoError("RSA private key primes p and q must be distinct factors of modulus n")
            lambda_n = lcm(self.p - 1, self.q - 1)
            if (self.e * self.d) % lambda_n != 1:
                phi_n = (self.p - 1) * (self.q - 1)
                if (self.e * self.d) % phi_n != 1:
                    raise CryptoError("RSA private exponent d is not a valid modular inverse of e")

    @property
    def public_key(self) -> RSAPublicKey:
        return RSAPublicKey(n=self.n, e=self.e)

    @property
    def bit_length(self) -> int:
        return self.n.bit_length()

    @property
    def is_production_grade(self) -> bool:
        return self.bit_length >= RECOMMENDED_PRODUCTION_RSA_BITS

    def format_security_summary(self) -> str:
        return self.public_key.format_security_summary()

    def to_bytes(self) -> bytes:
        buf = ByteBuffer()
        buf.write_bigint(self.n)
        buf.write_bigint(self.e)
        buf.write_bigint(self.d)
        buf.write_bigint(self.p)
        buf.write_bigint(self.q)
        return buf.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> "RSAPrivateKey":
        try:
            reader = ByteBuffer(data)
            n = reader.read_bigint()
            e = reader.read_bigint()
            d = reader.read_bigint()
            p = reader.read_bigint()
            q = reader.read_bigint()
            reader.assert_exhausted()
            return cls(n=n, e=e, d=d, p=p, q=q)
        except (SerializationError, CryptoError) as exc:
            raise CryptoError(f"Failed to deserialize RSAPrivateKey: {exc}") from exc


class RSACryptoEngine(AsymmetricCryptoInterface):
    """From-scratch RSA key-pair generator, signer, and verifier."""

    def __init__(
        self,
        hasher: HashInterface = default_hasher,
        miller_rabin_rounds: int = 40,
        rand_bytes_fn: Callable[[int], bytes] = random_bytes_csprng,
    ) -> None:
        self._hasher = hasher
        self._rounds = miller_rabin_rounds
        self._rand_bytes_fn = rand_bytes_fn

    def generate_keypair_objects(
        self, bit_length: int = DEFAULT_RSA_MODULUS_BITS
    ) -> Tuple[RSAPublicKey, RSAPrivateKey]:
        if isinstance(bit_length, bool) or not isinstance(bit_length, int) or bit_length < MIN_RSA_MODULUS_BITS:
            raise CryptoError(
                f"RSA bit_length must be an integer >= {MIN_RSA_MODULUS_BITS}, got {bit_length!r}"
            )

        prime_bits = bit_length // 2
        e = RSA_PUBLIC_EXPONENT

        while True:
            p = generate_large_prime(
                bit_length=prime_bits,
                rounds=self._rounds,
                rand_bytes_fn=self._rand_bytes_fn,
            )
            q = generate_large_prime(
                bit_length=bit_length - prime_bits,
                rounds=self._rounds,
                rand_bytes_fn=self._rand_bytes_fn,
            )
            if p == q:
                continue

            if abs(p - q).bit_length() < (prime_bits - 32):
                continue

            n = p * q
            if n.bit_length() < MIN_RSA_MODULUS_BITS:
                continue

            lambda_n = lcm(p - 1, q - 1)
            if gcd(e, lambda_n) != 1:
                continue

            d = mod_inverse(e, lambda_n)
            pub = RSAPublicKey(n=n, e=e)
            priv = RSAPrivateKey(n=n, e=e, d=d, p=p, q=q)
            return pub, priv

    def generate_keypair(
        self, bit_length: int = DEFAULT_RSA_MODULUS_BITS
    ) -> Tuple[bytes, bytes]:
        pub, priv = self.generate_keypair_objects(bit_length=bit_length)
        return pub.to_bytes(), priv.to_bytes()

    def _encode_message_representative(
        self, public_key: RSAPublicKey, message_bytes: bytes
    ) -> int:
        if not isinstance(message_bytes, (bytes, bytearray)):
            raise CryptoError("message_bytes must be bytes")
        pub_bytes = public_key.to_bytes()
        preimage = SIGNATURE_DOMAIN_TAG + pub_bytes + b"|" + bytes(message_bytes)
        digest = self._hasher.hash_bytes(preimage)
        rep_bytes = b"\x01" + digest + b"\xbc"
        m_int = int.from_bytes(rep_bytes, byteorder="big", signed=False)
        if m_int >= public_key.n:
            raise CryptoError("Message representative exceeds RSA modulus n")
        return m_int

    def sign(self, private_key_bytes: bytes, message_bytes: bytes) -> bytes:
        priv = RSAPrivateKey.from_bytes(private_key_bytes)
        pub = priv.public_key
        m_int = self._encode_message_representative(pub, message_bytes)

        sig_int = pow_mod(m_int, priv.d, priv.n)

        if pow_mod(sig_int, pub.e, pub.n) != m_int:
            raise CryptoError("Internal RSA signature self-verification failed")

        buf = ByteBuffer()
        buf.write_bigint(sig_int)
        return buf.to_bytes()

    def verify(
        self, public_key_bytes: bytes, message_bytes: bytes, signature_bytes: bytes
    ) -> bool:
        try:
            if not isinstance(public_key_bytes, (bytes, bytearray)) or not isinstance(
                signature_bytes, (bytes, bytearray)
            ):
                return False
            pub = RSAPublicKey.from_bytes(bytes(public_key_bytes))
            reader = ByteBuffer(bytes(signature_bytes))
            sig_int = reader.read_bigint()
            reader.assert_exhausted()

            if sig_int <= 1 or sig_int >= pub.n:
                return False

            expected_m_int = self._encode_message_representative(pub, message_bytes)
            recovered_m_int = pow_mod(sig_int, pub.e, pub.n)
            return recovered_m_int == expected_m_int
        except (CryptoError, SerializationError, TypeError, ValueError):
            return False


default_crypto_engine = RSACryptoEngine()
