"""
Phase 12: canonical-serialization property tests (stdlib `random`, fixed seed).

1. Round trip: random Transaction / Block -> to_bytes -> from_bytes -> equal object
   and identical bytes.
2. Truncation: every proper prefix of a serialization fails to parse.
3. Single-byte mutation: flipping any bit pattern in any byte of a real signed transfer
   or a real mined block either fails to parse or fails validation -- and never parses
   back to the original object (no encoding malleability).
"""

from __future__ import annotations

import random
import unittest

from blockchain_lite.crypto.asymmetric import MIN_RSA_MODULUS_BITS
from blockchain_lite.crypto.fast_hash import HashlibSHA256
from blockchain_lite.interfaces import TX_TYPE_COINBASE, TX_TYPE_TRANSFER, SerializationError, ValidationError
from blockchain_lite.ledger.chain import BlockchainLedger
from blockchain_lite.ledger.validator import FullChainValidator
from blockchain_lite.models.block import Block
from blockchain_lite.models.transaction import Transaction, TxInput, TxOutput
from blockchain_lite.wallet.wallet import Wallet

SEED = 20261015
FAST = HashlibSHA256()  # bit-identical to the default hasher; used only for speed
T0 = 1700000000


def _rand_bytes(rng: random.Random, n: int) -> bytes:
    return bytes(rng.getrandbits(8) for _ in range(n))


def _rand_tx(rng: random.Random) -> Transaction:
    outputs = tuple(TxOutput(amount=rng.randint(1, 10 ** 9), recipient_address=_rand_bytes(rng, 32))
                    for _ in range(rng.randint(1, 3)))
    if rng.random() < 0.3:
        return Transaction(tx_type=TX_TYPE_COINBASE, timestamp=rng.randrange(2 ** 64), inputs=(), outputs=outputs)
    inputs = tuple(
        TxInput(prev_tx_id=_rand_bytes(rng, 32), output_index=rng.randrange(2 ** 32),
                sender_pubkey=_rand_bytes(rng, rng.randint(1, 96)),
                signature=_rand_bytes(rng, rng.randint(0, 96)))
        for _ in range(rng.randint(1, 4)))
    return Transaction(tx_type=TX_TYPE_TRANSFER, timestamp=rng.randrange(2 ** 64), inputs=inputs, outputs=outputs)


def _rand_block(rng: random.Random) -> Block:
    return Block(index=rng.randrange(2 ** 32), previous_hash=_rand_bytes(rng, 32),
                 merkle_root=_rand_bytes(rng, 32), timestamp=rng.randrange(2 ** 64),
                 difficulty=rng.randint(0, 256), nonce=rng.randrange(2 ** 64),
                 transactions=tuple(_rand_tx(rng) for _ in range(rng.randint(1, 4))),
                 block_hash=_rand_bytes(rng, 32))


class TestRoundTrip(unittest.TestCase):
    def test_random_transactions_round_trip(self) -> None:
        rng = random.Random(SEED)
        for _ in range(300):
            tx = _rand_tx(rng)
            raw = tx.to_bytes()
            back = Transaction.from_bytes(raw)
            self.assertEqual(back, tx)
            self.assertEqual(back.to_bytes(), raw)

    def test_random_blocks_round_trip(self) -> None:
        rng = random.Random(SEED + 1)
        for _ in range(100):
            block = _rand_block(rng)
            raw = block.to_bytes()
            back = Block.from_bytes(raw)
            self.assertEqual(back, block)
            self.assertEqual(back.to_bytes(), raw)

    def test_every_proper_prefix_fails_to_parse(self) -> None:
        rng = random.Random(SEED + 2)
        for _ in range(20):
            raw = _rand_block(rng).to_bytes()
            for cut in range(len(raw)):
                with self.assertRaises(SerializationError, msg=f"prefix len {cut}"):
                    Block.from_bytes(raw[:cut])
            with self.assertRaises(SerializationError):
                Block.from_bytes(raw + b"\x00")  # trailing garbage


class TestSingleByteMutation(unittest.TestCase):
    MASKS = (0x01, 0x80)

    @classmethod
    def setUpClass(cls) -> None:
        cls.alice = Wallet.generate("A", bit_length=MIN_RSA_MODULUS_BITS)
        cls.bob = Wallet.generate("B", bit_length=MIN_RSA_MODULUS_BITS)
        ledger = BlockchainLedger(difficulty=4, hasher=FAST)
        ledger.create_genesis_block([(cls.alice.address, 100)], timestamp=T0)
        cls.tx = cls.alice.create_signed_transfer(
            cls.bob.address, 30, ledger.get_spendable_utxos(cls.alice.address), fee=1, timestamp=T0 + 1)
        cls.genesis_only = BlockchainLedger(difficulty=4, hasher=FAST)
        cls.genesis_only.load_verified_chain(ledger.blocks)
        ledger.submit_transaction(cls.tx)
        ledger.mine_pending_transactions(miner_address=cls.bob.address, timestamp=T0 + 10)
        cls.chain = ledger.blocks
        cls.validator = FullChainValidator(hasher=FAST, params=ledger.params)

    def _mutations(self, raw: bytes):
        for pos in range(len(raw)):
            for mask in self.MASKS:
                yield pos, raw[:pos] + bytes([raw[pos] ^ mask]) + raw[pos + 1:]

    def test_mutated_signed_transfer_never_accepted(self) -> None:
        raw = self.tx.to_bytes()
        parsed_count = 0
        for pos, mutated in self._mutations(raw):
            try:
                candidate = Transaction.from_bytes(mutated)
            except SerializationError:
                continue
            parsed_count += 1
            self.assertNotEqual(candidate, self.tx, f"byte {pos}: non-canonical encoding")
            with self.assertRaises(ValidationError, msg=f"mutated byte {pos} accepted"):
                self.genesis_only.submit_transaction(candidate)
        self.assertGreater(parsed_count, 0)  # the test must exercise the validation path
        self.assertEqual(self.genesis_only.mempool_size, 0)

    def test_mutated_block_never_validates(self) -> None:
        genesis, block = self.chain
        self.validator.validate_chain_or_raise([genesis, block])  # baseline is valid
        raw = block.to_bytes()
        parsed_count = 0
        for pos, mutated in self._mutations(raw):
            try:
                candidate = Block.from_bytes(mutated)
            except SerializationError:
                continue
            parsed_count += 1
            self.assertNotEqual(candidate, block, f"byte {pos}: non-canonical encoding")
            with self.assertRaises(ValidationError, msg=f"mutated byte {pos} validated"):
                self.validator.validate_chain_or_raise([genesis, candidate])
        self.assertGreater(parsed_count, len(raw))  # most mutations parse; validation must catch them


if __name__ == "__main__":
    unittest.main()
