"""
Phase 2 Automated Verification Suite (Worklet 1: Cryptographic Foundations & Transactions).
"""

from __future__ import annotations

import unittest

from blockchain_lite.crypto.asymmetric import (
    MIN_RSA_MODULUS_BITS,
    RSACryptoEngine,
    RSAPrivateKey,
    RSAPublicKey,
)
from blockchain_lite.crypto.hashing import default_hasher
from blockchain_lite.crypto.number_theory import (
    extended_gcd,
    gcd,
    generate_large_prime,
    is_probable_prime_miller_rabin,
    mod_add,
    mod_inverse,
    mod_mul,
    mod_sub,
    pow_mod,
    pow_mod_with_trace,
)
from blockchain_lite.interfaces import (
    CryptoError,
    DoubleSpendError,
    TamperDetectedError,
)
from blockchain_lite.models.transaction import (
    Transaction,
    TxInput,
    TxOutput,
    validate_block_transactions_no_double_spend,
    validate_transaction_integrity,
)
from blockchain_lite.wallet.wallet import SpendableUTXO, Wallet


class TestWorklet1NumberTheoryAndRSA(unittest.TestCase):
    """Test Worklet 1.1 & 1.2: Modular arithmetic, fast ModExp, Miller-Rabin, and RSA."""

    def test_modular_arithmetic_primitives(self) -> None:
        m = 97
        self.assertEqual(mod_add(90, 20, m), 13)
        self.assertEqual(mod_sub(10, 25, m), 82)
        self.assertEqual(mod_mul(12, 15, m), 83)

        g, x, y = extended_gcd(240, 46)
        self.assertEqual(g, 2)
        self.assertEqual(240 * x + 46 * y, 2)

        inv = mod_inverse(17, 3120)
        self.assertEqual(inv, 2753)
        self.assertEqual((17 * inv) % 3120, 1)

        with self.assertRaises(CryptoError):
            mod_inverse(12, 30)

    def test_fast_modular_exponentiation_and_trace(self) -> None:
        base = 0x123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
        exp = (1 << 512) + 0xFEDCBA9876543210
        mod = (1 << 521) - 1  # Mersenne prime M_521

        trace = pow_mod_with_trace(base, exp, mod)
        expected = pow(base, exp, mod)
        self.assertEqual(trace.result, expected)
        self.assertEqual(trace.exponent_bit_length, 513)
        self.assertLessEqual(trace.total_modular_ops, 2 * 513)

        self.assertEqual(pow_mod(12345, 0, 97), 1)
        self.assertEqual(pow_mod(12345, 5, 1), 0)

    def test_miller_rabin_primality_and_carmichael_rejection(self) -> None:
        known_primes = [
            2, 3, 5, 7, 13, 101, 1009, 104729,
            (1 << 31) - 1,
            (1 << 61) - 1,
            (1 << 89) - 1,
            (1 << 127) - 1,
        ]
        for p in known_primes:
            self.assertTrue(
                is_probable_prime_miller_rabin(p, rounds=40),
                f"Failed to identify prime {p}",
            )

        carmichael_and_composites = [
            0, 1, 4, 9, 15, 221, 341,
            561,    # 1st Carmichael number (3 * 11 * 17)
            1105,   # 2nd Carmichael number (5 * 13 * 17)
            1729,   # 3rd Carmichael / Hardy-Ramanujan number (7 * 13 * 19)
            2465,
            2821,
            6601,
            8911,
            41041,
            ((1 << 61) - 1) * ((1 << 31) - 1),
        ]
        for c in carmichael_and_composites:
            self.assertFalse(
                is_probable_prime_miller_rabin(c, rounds=40),
                f"Falsely accepted composite/Carmichael number {c}",
            )

    def test_large_prime_and_rsa_keypair_generation(self) -> None:
        p = generate_large_prime(bit_length=192, rounds=30)
        self.assertEqual(p.bit_length(), 192)
        self.assertTrue(is_probable_prime_miller_rabin(p, rounds=30))

        engine = RSACryptoEngine()
        pub, priv = engine.generate_keypair_objects(bit_length=MIN_RSA_MODULUS_BITS)
        self.assertGreaterEqual(pub.bit_length, MIN_RSA_MODULUS_BITS)
        self.assertEqual(pub.n, priv.p * priv.q)
        self.assertEqual(gcd(pub.e, (priv.p - 1) * (priv.q - 1)), 1)

        pub_restored = RSAPublicKey.from_bytes(pub.to_bytes())
        priv_restored = RSAPrivateKey.from_bytes(priv.to_bytes())
        self.assertEqual(pub, pub_restored)
        self.assertEqual(priv, priv_restored)

        msg = b"Canonical message payload for RSA signature verification"
        sig = engine.sign(priv.to_bytes(), msg)
        self.assertTrue(engine.verify(pub.to_bytes(), msg, sig))

        self.assertFalse(engine.verify(pub.to_bytes(), msg + b"!", sig))
        tampered_sig = bytearray(sig)
        tampered_sig[-1] ^= 0x01
        self.assertFalse(engine.verify(pub.to_bytes(), msg, bytes(tampered_sig)))


class TestWorklet1TransactionsWalletAndDoubleSpend(unittest.TestCase):
    """Test Worklet 1.3, 1.4 & 1.5: Wallet, Canonical Transactions, Tampering & Double-Spend."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = RSACryptoEngine()
        cls.alice = Wallet.generate(label="Alice", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=cls.engine)
        cls.bob = Wallet.generate(label="Bob", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=cls.engine)
        cls.charlie = Wallet.generate(label="Charlie", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=cls.engine)

    def test_wallet_key_isolation_and_watch_only(self) -> None:
        self.assertTrue(self.alice.can_sign)
        self.assertEqual(len(self.alice.address), 32)

        watch_alice = Wallet.watch_only(self.alice.public_key_bytes, label="Alice-Watch")
        self.assertFalse(watch_alice.can_sign)
        self.assertEqual(watch_alice.address, self.alice.address)
        with self.assertRaises(CryptoError):
            watch_alice.sign_bytes(b"cannot-sign")

    def test_transaction_creation_signing_and_canonical_serialization(self) -> None:
        genesis_tx = Transaction.create_coinbase(
            recipient_address=self.alice.address,
            amount=1000,
            timestamp=1700000000,
        )
        self.assertTrue(genesis_tx.verify_signatures())

        alice_utxos = [
            SpendableUTXO(
                tx_id=genesis_tx.tx_id,
                output_index=0,
                amount=1000,
                recipient_address=self.alice.address,
            )
        ]

        transfer_tx = self.alice.create_signed_transfer(
            recipient_address=self.bob.address,
            amount=350,
            spendable_utxos=alice_utxos,
            fee=10,
            timestamp=1700000060,
        )

        self.assertEqual(len(transfer_tx.inputs), 1)
        self.assertEqual(len(transfer_tx.outputs), 2)
        self.assertEqual(transfer_tx.outputs[0].amount, 350)
        self.assertEqual(transfer_tx.outputs[0].recipient_address, self.bob.address)
        self.assertEqual(transfer_tx.outputs[1].amount, 640)
        self.assertEqual(transfer_tx.outputs[1].recipient_address, self.alice.address)

        raw_bytes_1 = transfer_tx.to_bytes()
        restored_tx = Transaction.from_bytes(raw_bytes_1)
        raw_bytes_2 = restored_tx.to_bytes()
        self.assertEqual(raw_bytes_1, raw_bytes_2)
        self.assertEqual(transfer_tx.tx_id, restored_tx.tx_id)
        self.assertTrue(Wallet.verify_transaction(restored_tx))

    def test_one_byte_tampering_detection_in_transaction(self) -> None:
        utxo_tx_id = default_hasher.hash_bytes(b"seed-utxo-1")
        tx = self.alice.create_signed_transfer(
            recipient_address=self.bob.address,
            amount=250,
            spendable_utxos=[
                SpendableUTXO(
                    tx_id=utxo_tx_id,
                    output_index=0,
                    amount=500,
                    recipient_address=self.alice.address,
                )
            ],
            timestamp=1700000100,
        )
        validate_transaction_integrity(tx)

        tampered_amount_tx = Transaction(
            tx_type=tx.tx_type,
            timestamp=tx.timestamp,
            inputs=tx.inputs,
            outputs=(
                TxOutput(amount=251, recipient_address=self.bob.address),
                tx.outputs[1],
            ),
        )
        self.assertNotEqual(tx.tx_id, tampered_amount_tx.tx_id)
        self.assertFalse(tampered_amount_tx.verify_signatures())
        with self.assertRaises(TamperDetectedError):
            validate_transaction_integrity(tampered_amount_tx)

        tampered_recipient_tx = Transaction(
            tx_type=tx.tx_type,
            timestamp=tx.timestamp,
            inputs=tx.inputs,
            outputs=(
                TxOutput(amount=250, recipient_address=self.charlie.address),
                tx.outputs[1],
            ),
        )
        self.assertFalse(tampered_recipient_tx.verify_signatures())
        with self.assertRaises(TamperDetectedError):
            validate_transaction_integrity(tampered_recipient_tx)

        raw = bytearray(tx.to_bytes())
        raw[-3] ^= 0x04
        corrupted_tx = Transaction.from_bytes(bytes(raw))
        self.assertFalse(corrupted_tx.verify_signatures())
        with self.assertRaises(TamperDetectedError):
            validate_transaction_integrity(corrupted_tx)

    def test_intra_block_and_intra_tx_double_spend_prevention(self) -> None:
        seed_tx_id = default_hasher.hash_bytes(b"alice-funding-tx")
        utxo_outpoint = (seed_tx_id, 0)
        utxo_record = TxOutput(amount=500, recipient_address=self.alice.address)
        available_utxos = {utxo_outpoint: utxo_record}

        spendable = [
            SpendableUTXO(
                tx_id=seed_tx_id,
                output_index=0,
                amount=500,
                recipient_address=self.alice.address,
            )
        ]

        tx_to_bob = self.alice.create_signed_transfer(
            recipient_address=self.bob.address,
            amount=300,
            spendable_utxos=spendable,
            timestamp=1700000200,
        )
        tx_to_charlie = self.alice.create_signed_transfer(
            recipient_address=self.charlie.address,
            amount=400,
            spendable_utxos=spendable,
            timestamp=1700000201,
        )

        validate_block_transactions_no_double_spend([tx_to_bob], available_utxos=available_utxos)
        validate_block_transactions_no_double_spend([tx_to_charlie], available_utxos=available_utxos)

        with self.assertRaises(DoubleSpendError):
            validate_block_transactions_no_double_spend(
                [tx_to_bob, tx_to_charlie],
                available_utxos=available_utxos,
            )

        forged_unsigned = Transaction(
            tx_type=1,
            timestamp=1700000300,
            inputs=(
                TxInput(
                    prev_tx_id=seed_tx_id,
                    output_index=0,
                    sender_pubkey=self.bob.public_key_bytes,
                    signature=b"",
                ),
            ),
            outputs=(TxOutput(amount=500, recipient_address=self.bob.address),),
        )
        forged_signed_by_bob = self.bob.sign_transaction(forged_unsigned)
        with self.assertRaises(TamperDetectedError):
            validate_block_transactions_no_double_spend(
                [forged_signed_by_bob],
                available_utxos=available_utxos,
            )


if __name__ == "__main__":
    unittest.main()


class TestPhase2CryptographicHardening(unittest.TestCase):
    """Phase 2 Upgrade Tests: Boundary values, malformed keys, and invalid signature integers."""

    def test_number_theory_rejects_boolean_and_invalid_operands(self) -> None:
        with self.assertRaises(CryptoError):
            mod_add(True, 5, 11)  # type: ignore[arg-type]
        with self.assertRaises(CryptoError):
            mod_sub(5, False, 11)  # type: ignore[arg-type]
        with self.assertRaises(CryptoError):
            mod_mul(3.5, 2, 11)  # type: ignore[arg-type]
        with self.assertRaises(CryptoError):
            pow_mod(True, 5, 11)  # type: ignore[arg-type]
        with self.assertRaises(CryptoError):
            pow_mod(2, -1, 11)
        with self.assertRaises(CryptoError):
            mod_inverse(1, 1)

    def test_rsa_key_validation_rejects_even_modulus_and_mismatched_exponents(self) -> None:
        even_n = (1 << 400)  # Even integer cannot be a valid RSA semiprime
        with self.assertRaises(CryptoError):
            RSAPublicKey(n=even_n, e=65537)

        engine = RSACryptoEngine()
        pub, priv = engine.generate_keypair_objects(bit_length=MIN_RSA_MODULUS_BITS)

        # Mismatched private exponent d + 1 must fail mathematical consistency check
        with self.assertRaises(CryptoError):
            RSAPrivateKey(n=priv.n, e=priv.e, d=priv.d + 1, p=priv.p, q=priv.q)

        # Boundary signature integers (0, 1, n, n + 1) must be rejected safely by verify()
        from blockchain_lite.serialization import ByteBuffer
        for bad_sig_int in (0, 1, pub.n, pub.n + 1):
            buf = ByteBuffer()
            buf.write_bigint(bad_sig_int)
            self.assertFalse(engine.verify(pub.to_bytes(), b"msg", buf.to_bytes()))

        # Trailing garbage bytes on signature or public key must fail verification
        valid_sig = engine.sign(priv.to_bytes(), b"msg")
        self.assertFalse(engine.verify(pub.to_bytes(), b"msg", valid_sig + b"\x00"))
        self.assertFalse(engine.verify(pub.to_bytes() + b"\x00", b"msg", valid_sig))
