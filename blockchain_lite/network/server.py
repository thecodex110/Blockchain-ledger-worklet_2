"""
Ledger Server Dispatcher & Multi-Threaded TCP Socket Server (`ARC-001`).

Satisfies:
- Architecture: "the wallet (client) kept separate from the ledger; a client–server model."
- Exclusions: Built using standard library `socket` and `threading` with zero web frameworks.
"""

from __future__ import annotations

import logging
import secrets
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Optional, Tuple

from blockchain_lite.interfaces import (
    HASH_DIGEST_SIZE,
    MAX_UINT32,
    MAX_UINT64,
    BlockchainLiteError,
    DoubleSpendError,
    SerializationError,
    TamperDetectedError,
    ValidationError,
)
from blockchain_lite.ledger.chain import BlockchainLedger
from blockchain_lite.ledger.merkle import serialize_merkle_proof
from blockchain_lite.network.transport import (
    ClientTransport,
    NetworkRPCError,
    recv_framed_json,
    send_framed_json,
)

logger = logging.getLogger(__name__)

MAX_HEADERS_PER_REQUEST: int = 2000
MAX_RPC_MINING_DIFFICULTY: int = 20  # Practical upper bound for interactive RPC mining


class LedgerServerDispatcher:
    """
    Stateless request dispatcher sitting in front of an authoritative `BlockchainLedger`.
    Validates all incoming hex/byte/integer arguments and ensures private keys are never
    accepted or required by any server endpoint.

    Concurrency: no dispatcher-wide lock. `BlockchainLedger` guards its own state and
    mines outside its state lock, so reads proceed while a block is being mined.

    Key custody: the `private_key` field filter below is only a tripwire. The real
    guarantee is structural: no RPC method takes, needs, or returns a private key,
    because wallets sign client-side and submit signed bytes.

    Mining policy: `mine_block` is disabled unless `mine_token` is configured, and
    then requires `params["auth_token"]` to match. Client-chosen block timestamps are
    rejected unless `allow_client_timestamp=True` (deterministic tests/demos only).
    """

    def __init__(
        self,
        ledger: BlockchainLedger,
        mine_token: Optional[str] = None,
        allow_client_timestamp: bool = False,
    ) -> None:
        self._ledger = ledger
        self._mine_token = mine_token
        self._allow_client_timestamp = allow_client_timestamp

    @property
    def ledger(self) -> BlockchainLedger:
        return self._ledger

    def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Process a single RPC request dictionary and return a response envelope."""
        if not isinstance(request, dict):
            return self._error_response("ValidationError", "Request envelope must be a JSON object")

        method = request.get("method")
        if not isinstance(method, str) or not method:
            return self._error_response("ValidationError", "Request 'method' must be a non-empty string")

        params = request.get("params", {})
        if not isinstance(params, dict):
            return self._error_response("ValidationError", "'params' must be a JSON object")

        # Security boundary guardrail (THR-09): reject any payload containing private_key fields
        for k in params:
            if isinstance(k, str) and "private_key" in k.lower():
                return self._error_response(
                    "SecurityViolationError",
                    "Private keys must never be transmitted to the Ledger server",
                )

        try:
            result = self._dispatch(method, params)
            return {"ok": True, "result": result}
        except (
            TamperDetectedError,
            DoubleSpendError,
            ValidationError,
            SerializationError,
            BlockchainLiteError,
        ) as exc:
            logger.info("Rejected RPC %s: %s", method, type(exc).__name__)
            return self._error_response(type(exc).__name__, str(exc))
        except (KeyError, TypeError, ValueError) as exc:
            logger.info("Rejected RPC %s: invalid parameters", method)
            return self._error_response("ValidationError", f"Invalid request parameters: {exc}")

    # ------------------------------------------------------------------------
    # Strict Input Validation Helpers (F-002)
    # ------------------------------------------------------------------------

    @staticmethod
    def _require_hex_bytes(
        params: Dict[str, Any],
        key: str,
        expected_len: Optional[int] = None,
        max_len: int = 1024 * 1024,
    ) -> bytes:
        if key not in params:
            raise ValidationError(f"Missing required parameter '{key}'")
        raw_hex = params[key]
        if not isinstance(raw_hex, str):
            raise ValidationError(f"Parameter '{key}' must be a hex string, got {type(raw_hex).__name__}")
        try:
            data = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise ValidationError(f"Parameter '{key}' is not valid hexadecimal: {exc}") from exc
        if expected_len is not None and len(data) != expected_len:
            raise ValidationError(
                f"Parameter '{key}' must decode to exactly {expected_len} bytes, got {len(data)}"
            )
        if len(data) == 0 or len(data) > max_len:
            raise ValidationError(
                f"Parameter '{key}' byte length {len(data)} out of range [1, {max_len}]"
            )
        return data

    @staticmethod
    def _require_int(
        params: Dict[str, Any],
        key: str,
        min_val: int = 0,
        max_val: int = MAX_UINT64,
    ) -> int:
        if key not in params:
            raise ValidationError(f"Missing required parameter '{key}'")
        val = params[key]
        if isinstance(val, bool) or not isinstance(val, int):
            raise ValidationError(f"Parameter '{key}' must be an integer, got {type(val).__name__}")
        if val < min_val or val > max_val:
            raise ValidationError(
                f"Parameter '{key}' value {val} out of allowed range [{min_val}, {max_val}]"
            )
        return val

    # ------------------------------------------------------------------------
    # Method Dispatch
    # ------------------------------------------------------------------------

    def _dispatch(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if method == "get_chain_info":
            # Cached per tip; `{"full": true}` forces an O(n) re-validation.
            force = params.get("full") is True
            report = self._ledger.validate_full_chain(force=force) if self._ledger.height > 0 else None
            return {
                "height": self._ledger.height,
                "tip_hash_hex": self._ledger.tip.block_hash_hex if self._ledger.height > 0 else "",
                "genesis_hash_hex": self._ledger.genesis_hash.hex() if self._ledger.genesis_hash else "",
                "difficulty": self._ledger.difficulty,
                "block_reward": self._ledger.block_reward,
                "mempool_size": self._ledger.mempool_size,
                "total_supply": self._ledger.total_supply,
                "is_valid": report.is_valid if report else False,
            }

        if method == "get_balance":
            addr = self._require_hex_bytes(params, "address_hex", expected_len=HASH_DIGEST_SIZE)
            return {
                "address_hex": addr.hex(),
                "balance": self._ledger.get_balance(addr),
            }

        if method == "get_utxos":
            addr = self._require_hex_bytes(params, "address_hex", expected_len=HASH_DIGEST_SIZE)
            return {
                "address_hex": addr.hex(),
                "utxos": self._ledger.get_utxos_for_address(addr),
            }

        if method == "submit_transaction":
            tx_bytes = self._require_hex_bytes(params, "tx_bytes_hex", max_len=2 * 1024 * 1024)
            tx_id = self._ledger.submit_transaction(tx_bytes)
            return {
                "tx_id_hex": tx_id.hex(),
                "mempool_size": self._ledger.mempool_size,
            }

        if method == "mine_block":
            if self._mine_token is None:
                raise ValidationError("mine_block RPC is disabled (server started without a mine token)")
            sent = params.get("auth_token")
            if not isinstance(sent, str) or not secrets.compare_digest(
                sent.encode(), self._mine_token.encode()
            ):
                raise ValidationError("mine_block requires a valid auth_token")
            if params.get("timestamp") is not None and not self._allow_client_timestamp:
                raise ValidationError("Client-supplied block timestamps are disabled on this server")
            next_difficulty = self._ledger.calculate_next_difficulty()
            if next_difficulty > MAX_RPC_MINING_DIFFICULTY:
                raise ValidationError(
                    f"Ledger difficulty {next_difficulty} exceeds safe RPC limit {MAX_RPC_MINING_DIFFICULTY}"
                )
            miner_addr: Optional[bytes] = None
            if params.get("miner_address_hex") is not None:
                miner_addr = self._require_hex_bytes(
                    params, "miner_address_hex", expected_len=HASH_DIGEST_SIZE
                )
            timestamp: Optional[int] = None
            if params.get("timestamp") is not None:
                timestamp = self._require_int(params, "timestamp", min_val=0, max_val=MAX_UINT64)

            block, stats = self._ledger.mine_pending_transactions(
                miner_address=miner_addr,
                timestamp=timestamp,
            )
            logger.info("Mined block #%d hash=%s... hashes=%d in %.2fs",
                        block.index, block.block_hash_hex[:16], stats.hashes_tried, stats.elapsed_seconds)
            return {
                "block_index": block.index,
                "block_hash_hex": block.block_hash_hex,
                "previous_hash_hex": block.previous_hash_hex,
                "merkle_root_hex": block.merkle_root_hex,
                "nonce": block.nonce,
                "difficulty": block.difficulty,
                "tx_count": len(block.transactions),
                "hashes_tried": stats.hashes_tried,
                "elapsed_seconds": stats.elapsed_seconds,
                "block_bytes_hex": block.to_bytes().hex(),
            }

        if method == "get_block":
            idx = self._require_int(params, "block_index", min_val=0, max_val=MAX_UINT32)
            if idx >= self._ledger.height:
                raise ValidationError(f"Block index {idx} out of range (height={self._ledger.height})")
            block = self._ledger.get_block(idx)
            return {
                "block_index": block.index,
                "block_hash_hex": block.block_hash_hex,
                "previous_hash_hex": block.previous_hash_hex,
                "merkle_root_hex": block.merkle_root_hex,
                "timestamp": block.timestamp,
                "difficulty": block.difficulty,
                "nonce": block.nonce,
                "tx_ids": [tx.tx_id_hex for tx in block.transactions],
                "block_bytes_hex": block.to_bytes().hex(),
            }

        if method == "get_headers":
            # 88-byte PoW headers for SPV clients, which verify links/PoW/schedule themselves.
            start = self._require_int(params, "start_index", min_val=0, max_val=MAX_UINT32)
            count = self._require_int(params, "count", min_val=1, max_val=MAX_HEADERS_PER_REQUEST)
            end = min(start + count, self._ledger.height)
            return {
                "headers_hex": [self._ledger.get_block(i).header_bytes().hex() for i in range(start, end)],
            }

        if method == "get_merkle_proof":
            idx = self._require_int(params, "block_index", min_val=0, max_val=MAX_UINT32)
            tx_id = self._require_hex_bytes(params, "tx_id_hex", expected_len=HASH_DIGEST_SIZE)
            proof = self._ledger.get_merkle_proof(idx, tx_id)
            if proof is None:
                raise ValidationError(
                    f"Transaction {tx_id.hex()[:16]}... not found in block #{idx}"
                )
            return {
                "block_index": idx,
                "tx_id_hex": tx_id.hex(),
                "merkle_root_hex": proof.merkle_root.hex(),
                "proof_bytes_hex": serialize_merkle_proof(proof).hex(),
                "step_count": len(proof.steps),
            }

        if method == "get_transaction_history":
            addr = self._require_hex_bytes(params, "address_hex", expected_len=HASH_DIGEST_SIZE)
            return {
                "address_hex": addr.hex(),
                "history": self._ledger.get_transaction_history(addr),
            }

        raise ValidationError(f"Unknown RPC method: {method!r}")

    @staticmethod
    def _error_response(error_type: str, message: str) -> Dict[str, Any]:
        return {
            "ok": False,
            "error": {
                "type": error_type,
                "message": message,
            },
        }


class InMemoryTransport(ClientTransport):
    """
    Synchronous in-process transport that serializes every request through the
    exact same JSON/hex wire boundary as `TCPSocketTransport`.
    """

    def __init__(self, dispatcher: LedgerServerDispatcher) -> None:
        self._dispatcher = dispatcher

    def send_request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        response = self._dispatcher.handle_request({"method": method, "params": params})
        if not response.get("ok"):
            err = response.get("error", {})
            raise NetworkRPCError(
                err.get("type", "BlockchainLiteError"),
                err.get("message", "Unknown RPC error"),
            )
        return response["result"]


class TCPSocketLedgerServer:
    """
    Standard-library TCP Socket Server hosting a `LedgerServerDispatcher`.
    Supports context-manager lifecycle (`with TCPSocketLedgerServer(ledger) as server:`).
    """

    def __init__(
        self,
        ledger: BlockchainLedger,
        host: str = "127.0.0.1",
        port: int = 0,
        client_timeout: float = 5.0,
        max_workers: int = 32,
        mine_token: Optional[str] = None,
        allow_client_timestamp: bool = False,
    ) -> None:
        self._dispatcher = LedgerServerDispatcher(
            ledger, mine_token=mine_token, allow_client_timestamp=allow_client_timestamp
        )
        self._host = host
        self._requested_port = port
        self._client_timeout = client_timeout
        self._max_workers = max_workers
        self._server_sock: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._executor: Optional[ThreadPoolExecutor] = None
        self._running = threading.Event()
        self._bound_port: int = 0

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._bound_port

    @property
    def address(self) -> Tuple[str, int]:
        return (self._host, self._bound_port)

    def start(self) -> None:
        if self._running.is_set():
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self._host, self._requested_port))
        sock.listen(max(128, self._max_workers))
        sock.settimeout(0.2)
        self._bound_port = sock.getsockname()[1]
        self._server_sock = sock
        self._executor = ThreadPoolExecutor(
            max_workers=self._max_workers,
            thread_name_prefix="LedgerWorker",
        )
        self._running.set()
        self._accept_thread = threading.Thread(
            target=self._accept_loop,
            name="LedgerTCPServer",
            daemon=True,
        )
        self._accept_thread.start()
        dispatcher = self._dispatcher
        logger.info(
            "Ledger RPC server listening host=%s port=%d max_workers=%d mining_rpc=%s client_timestamps=%s",
            self._host, self._bound_port, self._max_workers,
            "enabled" if dispatcher._mine_token else "disabled", dispatcher._allow_client_timestamp,
        )

    def stop(self) -> None:
        self._running.clear()
        if self._server_sock is not None:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=2.0)
            self._accept_thread = None
        if self._executor is not None:
            self._executor.shutdown(wait=False, cancel_futures=True)
            self._executor = None

    def _accept_loop(self) -> None:
        while self._running.is_set() and self._server_sock is not None:
            try:
                client_sock, _ = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if self._executor is not None:
                try:
                    self._executor.submit(self._handle_client, client_sock)
                except RuntimeError:
                    # Server is shutting down
                    try:
                        client_sock.close()
                    except OSError:
                        pass
                    break

    def _handle_client(self, client_sock: socket.socket) -> None:
        with client_sock:
            client_sock.settimeout(self._client_timeout)
            try:
                while self._running.is_set():
                    try:
                        req = recv_framed_json(client_sock)
                    except SerializationError as exc:
                        err_resp = LedgerServerDispatcher._error_response(
                            "SerializationError", str(exc)
                        )
                        send_framed_json(client_sock, err_resp)
                        return
                    resp = self._dispatcher.handle_request(req)
                    send_framed_json(client_sock, resp)
            except (EOFError, OSError, SerializationError):
                return

    def __enter__(self) -> "TCPSocketLedgerServer":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()
