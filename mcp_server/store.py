"""Sealed key-value records on disk, for OAuth state that must survive restarts.

On Cloud Run the directory is a Cloud Storage volume (`/data`). Every record is
JSON sealed with AES-256-GCM under a key from Secret Manager (`MCP_SEAL_KEY`), and
the record's slot (kind + key) is the additional authenticated data, so a record
copied into another slot fails to open. File names are a hash of the key, so a
token never appears in a file name. Same design as ursa-bifrost and the Nexus MCP server.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import threading
import time
from collections.abc import Iterator
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_KIND = re.compile(r"^[a-z]{2,20}$")


class StoreError(RuntimeError):
    pass


def load_key(value: str) -> bytes:
    """A 32-byte key given as base64 (urlsafe or standard)."""
    raw = (value or "").strip()
    if not raw:
        raise StoreError("MCP_SEAL_KEY is not set")
    pad = "=" * (-len(raw) % 4)
    for decode in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            key = decode(raw + pad)
        except ValueError:
            continue
        if len(key) == 32:
            return key
    raise StoreError("MCP_SEAL_KEY must be 32 bytes, base64-encoded")


def new_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")


class SealedStore:
    def __init__(self, root: str, key: bytes) -> None:
        if len(key) != 32:
            raise StoreError("seal key must be 32 bytes")
        self.root = root
        self._aead = AESGCM(key)
        self._lock = threading.Lock()
        os.makedirs(root, mode=0o700, exist_ok=True)

    @staticmethod
    def _name(key: str) -> str:
        return hashlib.sha256(key.encode()).hexdigest()

    def _path(self, kind: str, key: str) -> str:
        if not _KIND.match(kind):
            raise StoreError(f"bad record kind {kind!r}")
        return os.path.join(self.root, kind, self._name(key))

    def put(self, kind: str, key: str, value: dict[str, Any]) -> None:
        path = self._path(kind, key)
        nonce = secrets.token_bytes(12)
        aad = f"{kind}/{self._name(key)}".encode()
        blob = nonce + self._aead.encrypt(nonce, json.dumps(value).encode(), aad)
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        tmp = f"{path}.{secrets.token_hex(4)}.tmp"
        with self._lock:
            # 0600 at creation (a Cloud Storage volume ignores later chmods).
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(blob)
            os.replace(tmp, path)

    def _open(self, kind: str, name: str) -> dict[str, Any] | None:
        path = os.path.join(self.root, kind, name)
        try:
            with open(path, "rb") as f:
                blob = f.read()
        except FileNotFoundError:
            return None
        if len(blob) < 13:
            return None
        try:
            plain = self._aead.decrypt(blob[:12], blob[12:], f"{kind}/{name}".encode())
            value = json.loads(plain)
        except Exception:
            return None
        if not isinstance(value, dict):
            return None
        exp = value.get("expires")
        if isinstance(exp, (int, float)) and exp < time.time():
            self._remove(kind, name)
            return None
        return value

    def get(self, kind: str, key: str) -> dict[str, Any] | None:
        self._path(kind, key)  # validates kind
        return self._open(kind, self._name(key))

    def _remove(self, kind: str, name: str) -> bool:
        try:
            os.remove(os.path.join(self.root, kind, name))
            return True
        except FileNotFoundError:
            return False

    def delete(self, kind: str, key: str) -> bool:
        self._path(kind, key)
        return self._remove(kind, self._name(key))

    def pop(self, kind: str, key: str) -> dict[str, Any] | None:
        """Read and delete in one step (single-use codes and refresh tokens)."""
        with self._lock:
            value = self.get(kind, key)
            if value is not None:
                self.delete(kind, key)
        return value

    def items(self, kind: str) -> Iterator[tuple[str, dict[str, Any]]]:
        """(file name, record) for every live record of a kind; expired ones are removed."""
        if not _KIND.match(kind):
            raise StoreError(f"bad record kind {kind!r}")
        folder = os.path.join(self.root, kind)
        try:
            names = os.listdir(folder)
        except FileNotFoundError:
            return
        for name in names:
            if name.endswith(".tmp") or len(name) != 64:
                continue
            value = self._open(kind, name)
            if value is not None:
                yield name, value

    def delete_name(self, kind: str, name: str) -> bool:
        if not _KIND.match(kind) or len(name) != 64:
            raise StoreError("bad record")
        return self._remove(kind, name)
