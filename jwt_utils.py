"""
jwt_utils.py
============
Implementasi JWT minimal dengan algoritma HS512 (HMAC-SHA512), dipakai untuk
mengamankan API RESTful /api/v1/* sebagai fitur pengayaan pada Topik A
(Rahmatulloh dkk., 2018 - JWT dengan HMAC-SHA512).

Sengaja ditulis manual (bukan library pihak ketiga) agar mekanismenya terlihat
jelas untuk keperluan laporan & presentasi, memakai hashlib/hmac yang sudah
teruji sebagai primitif dasarnya.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def generate_secret() -> str:
    """Kunci rahasia HMAC (server-side), dibangkitkan dengan CSPRNG."""
    return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")


def create_token(secret: str, claims: dict[str, Any], expires_in_seconds: int = 3600) -> str:
    header = {"alg": "HS512", "typ": "JWT"}
    now = int(time.time())
    payload = {**claims, "iat": now, "exp": now + expires_in_seconds}

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()

    signature = hmac.new(secret.encode(), signing_input, hashlib.sha512).digest()
    signature_b64 = _b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"


class TokenError(Exception):
    pass


def verify_token(secret: str, token: str) -> dict[str, Any]:
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
    except ValueError as exc:
        raise TokenError("Format token JWT tidak valid.") from exc

    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected_sig = hmac.new(secret.encode(), signing_input, hashlib.sha512).digest()
    actual_sig = _b64url_decode(signature_b64)

    if not hmac.compare_digest(expected_sig, actual_sig):
        raise TokenError("Tanda tangan token tidak valid.")

    payload = json.loads(_b64url_decode(payload_b64))
    if payload.get("exp", 0) < int(time.time()):
        raise TokenError("Token telah kedaluwarsa.")

    return payload
