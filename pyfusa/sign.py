"""HMAC-SHA256 file signing and verification."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets


def keygen(output_path: str) -> None:
    key = secrets.token_bytes(32).hex()
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(key + "\n")
    os.chmod(output_path, 0o600)


def _load_key(key_path: str) -> bytes:
    with open(key_path, encoding="utf-8") as f:
        return bytes.fromhex(f.read().strip())


def sign_file(target_path: str, key_path: str, sig_path: str = "") -> str:
    key = _load_key(key_path)
    with open(target_path, "rb") as f:
        data = f.read()
    sig = hmac.new(key, data, hashlib.sha256).hexdigest()
    if not sig_path:
        sig_path = target_path + ".sig"
    with open(sig_path, "w", encoding="utf-8") as f:
        f.write(sig + "\n")
    return sig_path


def verify_file(target_path: str, key_path: str, sig_path: str = "") -> bool:
    key = _load_key(key_path)
    if not sig_path:
        sig_path = target_path + ".sig"
    with open(target_path, "rb") as f:
        data = f.read()
    with open(sig_path, encoding="utf-8") as f:
        expected = bytes.fromhex(f.read().strip())
    computed = hmac.new(key, data, hashlib.sha256).digest()
    return hmac.compare_digest(computed, expected)
