from __future__ import annotations

import json
import socket

from .core import NetworkEvidence


class RedisNetworkContextStore:
    """Small dependency-free Redis writer for short-lived network context."""

    def __init__(self, host: str = "127.0.0.1", port: int = 6379, timeout_seconds: float = 0.25) -> None:
        self._host = host
        self._port = port
        self._timeout_seconds = timeout_seconds

    def put(self, source_ip: str, evidence: NetworkEvidence, ttl_seconds: int) -> None:
        payload = json.dumps(evidence.as_redis_value(), separators=(",", ":"), sort_keys=True)
        response = self._command("SET", self.key(source_ip), payload, "EX", str(ttl_seconds))
        if response != "OK":
            raise ConnectionError(f"Redis SET failed: {response}")

    def ping(self) -> bool:
        try:
            return self._command("PING") == "PONG"
        except OSError:
            return False

    @staticmethod
    def key(source_ip: str) -> str:
        return f"waf:network:{source_ip.replace(':', '_')}"

    def _command(self, *parts: str) -> str:
        encoded = self._encode(*parts)
        with socket.create_connection((self._host, self._port), timeout=self._timeout_seconds) as connection:
            connection.settimeout(self._timeout_seconds)
            connection.sendall(encoded)
            prefix = self._read_exact(connection, 1)
            line = self._read_line(connection)
        if prefix == b"+":
            return line
        if prefix == b"-":
            raise ConnectionError(f"Redis error: {line}")
        raise ConnectionError("unsupported Redis response")

    @staticmethod
    def _encode(*parts: str) -> bytes:
        encoded = [f"*{len(parts)}\r\n".encode()]
        for part in parts:
            value = part.encode("utf-8")
            encoded.extend((f"${len(value)}\r\n".encode(), value, b"\r\n"))
        return b"".join(encoded)

    @staticmethod
    def _read_exact(connection: socket.socket, size: int) -> bytes:
        value = connection.recv(size)
        if len(value) != size:
            raise ConnectionError("Redis connection closed early")
        return value

    @staticmethod
    def _read_line(connection: socket.socket) -> str:
        chunks = bytearray()
        while not chunks.endswith(b"\r\n"):
            next_byte = connection.recv(1)
            if not next_byte:
                raise ConnectionError("Redis connection closed early")
            chunks.extend(next_byte)
        return chunks[:-2].decode("utf-8")
