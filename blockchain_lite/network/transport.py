"""
Wire-Framing & Transport Abstractions for Client-Server Communication (`ARC-001`).

Protocol Framing:
- Every request and response over TCP is framed with a 4-byte unsigned big-endian
  byte length (`>I`) followed by a UTF-8 JSON envelope containing canonical hex-encoded
  binary payloads.
- Built exclusively with Python's standard library (`socket`, `json`, `struct`)
  with zero web frameworks (`CON-001`).
"""

from __future__ import annotations

import json
import socket
import struct
from abc import ABC, abstractmethod
from typing import Any, Dict

from blockchain_lite.interfaces import BlockchainLiteError, SerializationError

MAX_FRAME_BYTES: int = 16 * 1024 * 1024  # 16 MB safety cap


class NetworkRPCError(BlockchainLiteError):
    """Raised when a client-server RPC call returns an error or transport fails."""

    def __init__(self, error_type: str, message: str) -> None:
        super().__init__(f"[{error_type}] {message}")
        self.error_type = error_type
        self.error_message = message


class ClientTransport(ABC):
    """Abstract client-to-server request/response transport."""

    @abstractmethod
    def send_request(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Send an RPC request to the Ledger server and return the `result` dictionary."""


def send_framed_json(sock: socket.socket, payload: Dict[str, Any]) -> None:
    """Write a 4-byte big-endian length-prefixed JSON message to `sock`."""
    if not isinstance(payload, dict):
        raise SerializationError("Framed JSON payload must be a dictionary")
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(raw) > MAX_FRAME_BYTES:
        raise SerializationError(f"Outbound RPC frame size {len(raw)} exceeds limit {MAX_FRAME_BYTES}")
    header = struct.pack(">I", len(raw))
    sock.sendall(header + raw)


def recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """Read exactly `num_bytes` from `sock` or raise `EOFError` if closed early."""
    buf = bytearray()
    while len(buf) < num_bytes:
        chunk = sock.recv(num_bytes - len(buf))
        if not chunk:
            raise EOFError("Socket connection closed before frame was completely read")
        buf.extend(chunk)
    return bytes(buf)


def recv_framed_json(sock: socket.socket) -> Dict[str, Any]:
    """Read a 4-byte big-endian length-prefixed JSON message from `sock`."""
    header = recv_exact(sock, 4)
    (frame_len,) = struct.unpack(">I", header)
    if frame_len == 0 or frame_len > MAX_FRAME_BYTES:
        raise SerializationError(
            f"RPC frame length {frame_len} out of valid range [1, {MAX_FRAME_BYTES}]"
        )
    raw = recv_exact(sock, frame_len)
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SerializationError(f"Malformed UTF-8 or JSON in RPC frame: {exc}") from exc

    if not isinstance(decoded, dict):
        raise SerializationError(
            f"RPC frame root must be a JSON object, got {type(decoded).__name__}"
        )
    return decoded
