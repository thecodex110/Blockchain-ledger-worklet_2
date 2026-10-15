"""
Phase 5 End-to-End Integration Test Suite (`ARC-001` & Full System Integration):
- Verifies Client-Server separation over both `InMemoryTransport` and live
  `TCPSocketLedgerServer` / `TCPSocketTransport`.
- Verifies that attempting to send a private key parameter to the server is
  explicitly rejected (`SecurityViolationError`).
- Verifies SPV Merkle proof verification, multi-wallet transfers, double-spend
  rejection over RPC, and the complete demonstration harness (`run_complete_demonstration`).
"""

from __future__ import annotations

import unittest

from blockchain_lite.cli.demo import run_complete_demonstration
from blockchain_lite.crypto.asymmetric import MIN_RSA_MODULUS_BITS, RSACryptoEngine
from blockchain_lite.ledger.chain import BlockchainLedger
from blockchain_lite.network.client import TCPSocketTransport, WalletClient
from blockchain_lite.network.server import (
    InMemoryTransport,
    LedgerServerDispatcher,
    TCPSocketLedgerServer,
)
from blockchain_lite.network.transport import NetworkRPCError
from blockchain_lite.wallet.wallet import Wallet


class TestPhase5ClientServerIntegration(unittest.TestCase):
    """End-to-end integration tests across Worklets 1, 2, and 3 over Client-Server RPC."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.engine = RSACryptoEngine()
        cls.alice = Wallet.generate("Alice", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=cls.engine)
        cls.bob = Wallet.generate("Bob", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=cls.engine)
        cls.miner = Wallet.generate("Miner", bit_length=MIN_RSA_MODULUS_BITS, crypto_engine=cls.engine)

    def test_tcp_socket_client_server_end_to_end_workflow(self) -> None:
        ledger = BlockchainLedger(difficulty=6, block_reward=50, crypto_engine=self.engine)
        ledger.create_genesis_block(
            initial_allocations=[(self.alice.address, 1000)],
            timestamp=1700000000,
        )

        with TCPSocketLedgerServer(ledger, host="127.0.0.1", port=0, mine_token="demo-mine-token", allow_client_timestamp=True) as server:
            self.assertGreater(server.port, 0)
            transport = TCPSocketTransport(server.host, server.port)

            alice_client = WalletClient(self.alice, transport)
            bob_client = WalletClient(self.bob, transport)
            miner_client = WalletClient(self.miner, transport)

            # Check initial state over TCP
            info = alice_client.get_chain_info()
            self.assertEqual(info["height"], 1)
            self.assertTrue(info["is_valid"])
            self.assertEqual(alice_client.get_balance(), 1000)
            self.assertEqual(bob_client.get_balance(), 0)

            # Alice sends 400 to Bob with fee 10 over TCP
            signed_tx = alice_client.send_funds(
                recipient_address=self.bob.address,
                amount=400,
                fee=10,
                timestamp=1700000060,
            )

            # Mine Block 1 over TCP
            mine_res = miner_client.request_mining(reward_to_self=True, timestamp=1700000065, auth_token="demo-mine-token")
            self.assertEqual(mine_res["block_index"], 1)
            self.assertEqual(mine_res["tx_count"], 2)  # Coinbase + Alice->Bob transfer

            # Verify updated balances over TCP
            self.assertEqual(alice_client.get_balance(), 590)
            self.assertEqual(bob_client.get_balance(), 400)
            self.assertEqual(miner_client.get_balance(), 60)  # 50 reward + 10 fee

            # Verify SPV Merkle inclusion proof over TCP
            self.assertTrue(
                bob_client.verify_transaction_inclusion_spv(
                    block_index=1, tx_id=signed_tx.tx_id
                )
            )

            # Verify transaction history over TCP
            alice_hist = alice_client.get_transaction_history()
            self.assertEqual(len(alice_hist), 2)

    def test_server_rejects_any_private_key_transmission(self) -> None:
        """Verify THR-09 control: Ledger server refuses any request containing private_key fields."""
        ledger = BlockchainLedger(difficulty=4, block_reward=50, crypto_engine=self.engine)
        dispatcher = LedgerServerDispatcher(ledger)
        transport = InMemoryTransport(dispatcher)

        with self.assertRaises(NetworkRPCError) as ctx:
            transport.send_request(
                "get_balance",
                {
                    "address_hex": self.alice.address_hex,
                    "private_key": "forbidden-secret",
                },
            )
        self.assertEqual(ctx.exception.error_type, "SecurityViolationError")

    def test_complete_cli_demonstration_harness_runs_cleanly(self) -> None:
        transcript = run_complete_demonstration()
        self.assertIn("WORKLET 1: NUMBER THEORY", transcript)
        self.assertIn("CLIENT-SERVER LEDGER & WALLET WORKFLOW OVER TCP SOCKETS", transcript)
        self.assertIn("WORKLET 2: BIT-LEVEL HASH AVALANCHE & MERKLE INCLUSION PROOF", transcript)
        self.assertIn("WORKLET 3: 1-BYTE TAMPER CASCADE, FORK RESOLUTION & PERSISTENCE", transcript)
        self.assertIn("WORKLET 3.5: PROOF-OF-WORK DIFFICULTY VS. MINING TIME BENCHMARK", transcript)


    def test_phase5_malformed_requests_missing_keys_and_concurrent_double_spends(self) -> None:
        """
        Verify F-002 & F-006:
        - Missing keys, wrong types, invalid hex strings, and malformed raw TCP frames
          fail safely with structured error responses without crashing the server or
          corrupting ledger state.
        - Concurrent threads attempting to spend the same UTXO over TCP result in
          exactly 1 accepted transaction and 1 DoubleSpendError rejection.
        """
        import socket
        import struct
        import threading
        from blockchain_lite.network.transport import recv_framed_json

        ledger = BlockchainLedger(difficulty=4, block_reward=50, crypto_engine=self.engine)
        ledger.create_genesis_block(
            initial_allocations=[(self.alice.address, 1000)],
            timestamp=1700000000,
        )

        with TCPSocketLedgerServer(ledger, host="127.0.0.1", port=0, mine_token="demo-mine-token", allow_client_timestamp=True) as server:
            transport = TCPSocketTransport(server.host, server.port)

            # 1. Missing required key "address_hex" -> structured ValidationError
            with self.assertRaises(NetworkRPCError) as ctx1:
                transport.send_request("get_balance", {})
            self.assertEqual(ctx1.exception.error_type, "ValidationError")

            # 2. Invalid hex string -> structured ValidationError
            with self.assertRaises(NetworkRPCError) as ctx2:
                transport.send_request("get_balance", {"address_hex": "not-valid-hex!!"})
            self.assertEqual(ctx2.exception.error_type, "ValidationError")

            # 3. Wrong byte length for address -> structured ValidationError
            with self.assertRaises(NetworkRPCError) as ctx3:
                transport.send_request("get_balance", {"address_hex": "abcd"})
            self.assertEqual(ctx3.exception.error_type, "ValidationError")

            # 4. Boolean passed as integer block_index -> structured ValidationError
            with self.assertRaises(NetworkRPCError) as ctx4:
                transport.send_request("get_block", {"block_index": True})
            self.assertEqual(ctx4.exception.error_type, "ValidationError")

            # 5. Raw malformed non-JSON frame over TCP -> returns SerializationError envelope
            with socket.create_connection((server.host, server.port), timeout=3.0) as raw_sock:
                bad_payload = b"{not-valid-json"
                raw_sock.sendall(struct.pack(">I", len(bad_payload)) + bad_payload)
                resp = recv_framed_json(raw_sock)
                self.assertFalse(resp["ok"])
                self.assertEqual(resp["error"]["type"], "SerializationError")

            # 6. Truncated connection mid-frame does not crash server
            with socket.create_connection((server.host, server.port), timeout=3.0) as trunc_sock:
                trunc_sock.sendall(struct.pack(">I", 100) + b"short")
            # Server still responds to normal requests afterwards
            alice_client = WalletClient(self.alice, transport)
            self.assertEqual(alice_client.get_balance(), 1000)

            # 7. Concurrent double-spend race test across 4 threads over TCP
            utxos = alice_client.get_spendable_utxos()
            competing_txs = [
                self.alice.create_signed_transfer(
                    recipient_address=self.bob.address,
                    amount=200 + i * 10,
                    spendable_utxos=utxos,
                    timestamp=1700001000 + i,
                )
                for i in range(4)
            ]
            successes: list[str] = []
            double_spend_errors: list[str] = []
            lock = threading.Lock()

            def submit_worker(tx_obj):
                try:
                    res = transport.send_request(
                        "submit_transaction",
                        {"tx_bytes_hex": tx_obj.to_bytes().hex()},
                    )
                    with lock:
                        successes.append(res["tx_id_hex"])
                except NetworkRPCError as exc:
                    with lock:
                        double_spend_errors.append(exc.error_type)

            threads = [threading.Thread(target=submit_worker, args=(tx,)) for tx in competing_txs]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            self.assertEqual(len(successes), 1)
            self.assertEqual(double_spend_errors, ["DoubleSpendError"] * 3)


if __name__ == "__main__":
    unittest.main()
