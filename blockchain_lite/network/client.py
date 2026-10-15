"""
Wallet Network Client & TCP Socket Transport (`ARC-001`).

Satisfies:
- Architecture: "the wallet (client) kept separate from the ledger; a client–server model."
- Worklet 1.3 & 1.4: Client-side transaction signing and canonical serialization.
- Worklet 2.3: Client-side SPV Merkle inclusion proof verification.
"""

from __future__ import annotations

import socket
import time
from typing import Any, Dict, List, Optional

from blockchain_lite.crypto.hashing import default_hasher
from blockchain_lite.interfaces import HashInterface, SerializationError, TamperDetectedError, ValidationError
from blockchain_lite.ledger.consensus import ConsensusParams, check_timestamp, expected_difficulty
from blockchain_lite.ledger.merkle import MerkleTree, deserialize_merkle_proof
from blockchain_lite.ledger.pow import hash_meets_difficulty
from blockchain_lite.models.block import BlockHeader
from blockchain_lite.models.transaction import Transaction
from blockchain_lite.network.transport import (
    ClientTransport,
    NetworkRPCError,
    recv_framed_json,
    send_framed_json,
)
from blockchain_lite.wallet.wallet import SpendableUTXO, Wallet


class TCPSocketTransport(ClientTransport):
    """
    Client transport that connects over TCP sockets (`127.0.0.1:<port>`) to a
    running `TCPSocketLedgerServer`.
    """

    def __init__(self, host: str, port: int, timeout: float = 5.0) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout

    def send_request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        with socket.create_connection((self._host, self._port), timeout=self._timeout) as sock:
            send_framed_json(sock, {"method": method, "params": params})
            response = recv_framed_json(sock)

        if not response.get("ok"):
            err = response.get("error", {})
            raise NetworkRPCError(
                err.get("type", "BlockchainLiteError"),
                err.get("message", "Unknown RPC error"),
            )
        return response["result"]


class WalletClient:
    """
    High-level Digital Wallet Client separated from the Ledger Server.

    Security Boundary:
    - Holds `self.wallet` (including the private key) strictly on the client side.
    - Communicates with the Ledger exclusively via `ClientTransport` RPC messages.
    - Constructs and signs transactions locally before transmitting only the
      canonically serialized signed transaction bytes to the server.
    """

    def __init__(self, wallet: Wallet, transport: ClientTransport) -> None:
        self._wallet = wallet
        self._transport = transport

    @property
    def wallet(self) -> Wallet:
        return self._wallet

    @property
    def address(self) -> bytes:
        return self._wallet.address

    @property
    def address_hex(self) -> str:
        return self._wallet.address_hex

    def get_chain_info(self) -> Dict[str, Any]:
        return self._transport.send_request("get_chain_info", {})

    def get_balance(self) -> int:
        res = self._transport.send_request(
            "get_balance", {"address_hex": self._wallet.address_hex}
        )
        return int(res["balance"])

    def get_spendable_utxos(self) -> List[SpendableUTXO]:
        res = self._transport.send_request(
            "get_utxos", {"address_hex": self._wallet.address_hex}
        )
        utxos: List[SpendableUTXO] = []
        for item in res["utxos"]:
            utxos.append(
                SpendableUTXO(
                    tx_id=bytes.fromhex(item["tx_id"]),
                    output_index=int(item["output_index"]),
                    amount=int(item["amount"]),
                    recipient_address=bytes.fromhex(item["recipient_address"]),
                )
            )
        return utxos

    def send_funds(
        self,
        recipient_address: bytes,
        amount: int,
        fee: int = 0,
        timestamp: Optional[int] = None,
    ) -> Transaction:
        """
        1. Query the Ledger server for this wallet's currently unspent outputs.
        2. Locally build and sign a canonical `Transaction` inside `self._wallet`.
        3. Transmit only the signed `tx.to_bytes()` over the transport to the Ledger server.
        4. Return the signed `Transaction` object.
        """
        utxos = self.get_spendable_utxos()
        signed_tx = self._wallet.create_signed_transfer(
            recipient_address=recipient_address,
            amount=amount,
            spendable_utxos=utxos,
            fee=fee,
            timestamp=timestamp,
        )
        res = self._transport.send_request(
            "submit_transaction",
            {"tx_bytes_hex": signed_tx.to_bytes().hex()},
        )
        if res.get("tx_id_hex") != signed_tx.tx_id_hex:
            raise NetworkRPCError(
                "ProtocolError",
                f"Server acknowledged tx_id {res.get('tx_id_hex')!r}, expected {signed_tx.tx_id_hex}",
            )
        return signed_tx

    def request_mining(
        self,
        reward_to_self: bool = True,
        timestamp: Optional[int] = None,
        auth_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Request the Ledger server to mine pending mempool transactions."""
        params: Dict[str, Any] = {}
        if auth_token is not None:
            params["auth_token"] = auth_token
        if reward_to_self:
            params["miner_address_hex"] = self._wallet.address_hex
        if timestamp is not None:
            params["timestamp"] = timestamp
        return self._transport.send_request("mine_block", params)

    def fetch_verified_headers(
        self,
        up_to_index: int,
        trusted_genesis_hash: bytes,
        params: ConsensusParams,
        hasher: HashInterface = default_hasher,
    ) -> List[BlockHeader]:
        """
        Download headers 0..`up_to_index` and verify them locally: genesis matches the
        out-of-band trust anchor, every header links to its predecessor's hash, meets
        its PoW target, declares exactly the consensus-scheduled difficulty, and obeys
        the timestamp rules. Raises ValidationError / SerializationError on any failure.

        Limitation: this proves the headers are a valid chain from the trusted genesis,
        not that it is the heaviest chain (the server could withhold a better one).
        """
        res = self._transport.send_request(
            "get_headers", {"start_index": 0, "count": up_to_index + 1}
        )
        headers = [BlockHeader.from_bytes(bytes.fromhex(h)) for h in res["headers_hex"]]
        if len(headers) != up_to_index + 1:
            raise ValidationError(f"Server returned {len(headers)} headers, expected {up_to_index + 1}")
        now = int(time.time())
        prev_hash = b""
        for i, header in enumerate(headers):
            digest = header.compute_hash(hasher)
            if header.index != i:
                raise ValidationError(f"Header {i} claims index {header.index}")
            if i == 0 and digest != trusted_genesis_hash:
                raise TamperDetectedError("Genesis header does not match the trusted genesis hash")
            if i > 0 and header.previous_hash != prev_hash:
                raise TamperDetectedError(f"Header {i} does not link to header {i - 1}")
            if not hash_meets_difficulty(digest, header.difficulty):
                raise TamperDetectedError(f"Header {i} fails its proof-of-work target")
            required = expected_difficulty(headers[:i], params)
            if header.difficulty != required:
                raise TamperDetectedError(
                    f"Header {i} declares difficulty {header.difficulty}, consensus requires {required}"
                )
            check_timestamp(header, headers[:i], now)
            prev_hash = digest
        return headers

    def verify_transaction_inclusion_spv(
        self,
        block_index: int,
        tx_id: bytes,
        trusted_genesis_hash: Optional[bytes] = None,
        params: Optional[ConsensusParams] = None,
    ) -> bool:
        """
        Light-Client / Simplified Payment Verification (SPV): verify locally that `tx_id`
        is committed inside block `block_index`'s Merkle root using an O(log2 N) proof.

        With `trusted_genesis_hash` (recommended), the Merkle root comes from a header
        chain the client verified itself (`fetch_verified_headers`), so a lying server
        must out-mine the honest chain from genesis at the scheduled difficulty.
        Without it (legacy), the root is whatever the same server reports, i.e. the
        client trusts the server.
        """
        if trusted_genesis_hash is not None:
            try:
                headers = self.fetch_verified_headers(
                    block_index, trusted_genesis_hash, params or ConsensusParams()
                )
            except (ValidationError, SerializationError):
                return False
            expected_merkle_root = headers[block_index].merkle_root
        else:
            block_res = self._transport.send_request(
                "get_block", {"block_index": block_index}
            )
            expected_merkle_root = bytes.fromhex(block_res["merkle_root_hex"])

        proof_res = self._transport.send_request(
            "get_merkle_proof",
            {"block_index": block_index, "tx_id_hex": tx_id.hex()},
        )
        proof = deserialize_merkle_proof(bytes.fromhex(proof_res["proof_bytes_hex"]))
        return MerkleTree.verify_proof(
            proof, expected_merkle_root=expected_merkle_root
        )

    def get_transaction_history(self) -> List[Dict[str, Any]]:
        res = self._transport.send_request(
            "get_transaction_history", {"address_hex": self._wallet.address_hex}
        )
        return list(res["history"])
