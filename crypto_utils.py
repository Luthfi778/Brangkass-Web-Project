"""
crypto_utils.py
================
Modul inti kriptografi untuk aplikasi "Brangkass".

Menyediakan:
- Derivasi kunci dari kata sandi (PBKDF2, scrypt, Argon2id) dengan salt acak
- Enkripsi/dekripsi AEAD modern: AES-256-GCM dan ChaCha20-Poly1305
- Format "blob" biner yang menyimpan salt, nonce, parameter KDF, dan cipherteks+tag
  menjadi satu, sehingga bisa disimpan/dipindahkan sebagai satu kesatuan (Base64/hex)
- Fungsi metrik pengujian: avalanche effect, entropi Shannon, histogram byte,
  serta pembanding waktu proses antar algoritma (untuk keperluan benchmark)

Seluruh pembangkitan bilangan acak memakai `os.urandom` (CSPRNG), sesuai
ketentuan tugas (tidak boleh pakai random biasa untuk kunci/IV/nonce/salt).
"""

from __future__ import annotations

import hashlib
import math
import os
import struct
import time
from dataclasses import dataclass
from typing import Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes

try:
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
    ARGON2_AVAILABLE = True
except Exception:  # pragma: no cover - argon2-cffi opsional
    ARGON2_AVAILABLE = False


# --------------------------------------------------------------------------- #
# Konstanta format blob
# --------------------------------------------------------------------------- #
MAGIC = b"BRKS"                 # penanda format Brangkass
VERSION = 1

ALGO_AES_GCM = 0
ALGO_CHACHA20_POLY1305 = 1
ALGO_NAMES = {ALGO_AES_GCM: "AES-256-GCM", ALGO_CHACHA20_POLY1305: "ChaCha20-Poly1305"}
ALGO_IDS = {v: k for k, v in ALGO_NAMES.items()}

KDF_PBKDF2 = 0
KDF_SCRYPT = 1
KDF_ARGON2ID = 2
KDF_NAMES = {KDF_PBKDF2: "PBKDF2-HMAC-SHA256", KDF_SCRYPT: "scrypt", KDF_ARGON2ID: "Argon2id"}
KDF_IDS = {v: k for k, v in KDF_NAMES.items()}

SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32  # 256-bit

DEFAULT_PBKDF2_ITER = 200_000
DEFAULT_SCRYPT_N = 2 ** 14  # 16384
DEFAULT_ARGON2_TIME_COST = 3
DEFAULT_ARGON2_MEMORY_KB = 65536  # 64 MB


class DecryptionError(Exception):
    """Dilempar bila kata sandi salah atau cipherteks telah diubah (tag gagal verifikasi)."""


# --------------------------------------------------------------------------- #
# Key derivation
# --------------------------------------------------------------------------- #
def derive_key(password: str, salt: bytes, kdf_id: int, cost_param: int) -> bytes:
    """Menurunkan kunci 256-bit dari kata sandi + salt memakai KDF yang dipilih.

    cost_param artinya berbeda tergantung KDF:
      - PBKDF2   -> jumlah iterasi
      - scrypt   -> N (harus pangkat 2)
      - Argon2id -> time_cost (memory_cost & parallelism memakai nilai default aman)
    """
    pwd_bytes = password.encode("utf-8")

    if kdf_id == KDF_PBKDF2:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN, salt=salt, iterations=cost_param)
        return kdf.derive(pwd_bytes)

    if kdf_id == KDF_SCRYPT:
        kdf = Scrypt(salt=salt, length=KEY_LEN, n=cost_param, r=8, p=1)
        return kdf.derive(pwd_bytes)

    if kdf_id == KDF_ARGON2ID:
        if not ARGON2_AVAILABLE:
            raise RuntimeError("argon2-cffi belum terpasang. Jalankan: pip install argon2-cffi")
        return hash_secret_raw(
            secret=pwd_bytes,
            salt=salt,
            time_cost=cost_param,
            memory_cost=DEFAULT_ARGON2_MEMORY_KB,
            parallelism=2,
            hash_len=KEY_LEN,
            type=Argon2Type.ID,
        )

    raise ValueError(f"KDF tidak dikenal: {kdf_id}")


def default_cost_for(kdf_id: int) -> int:
    return {
        KDF_PBKDF2: DEFAULT_PBKDF2_ITER,
        KDF_SCRYPT: DEFAULT_SCRYPT_N,
        KDF_ARGON2ID: DEFAULT_ARGON2_TIME_COST,
    }[kdf_id]


# --------------------------------------------------------------------------- #
# AEAD encrypt/decrypt (operasi mentah, tanpa pembungkusan blob)
# --------------------------------------------------------------------------- #
def _aead_for(algo_id: int, key: bytes):
    if algo_id == ALGO_AES_GCM:
        return AESGCM(key)
    if algo_id == ALGO_CHACHA20_POLY1305:
        return ChaCha20Poly1305(key)
    raise ValueError(f"Algoritma tidak dikenal: {algo_id}")


def raw_encrypt(algo_id: int, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Mengembalikan ciphertext yang sudah menyertakan authentication tag di akhir."""
    aead = _aead_for(algo_id, key)
    return aead.encrypt(nonce, plaintext, aad if aad else None)


def raw_decrypt(algo_id: int, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    aead = _aead_for(algo_id, key)
    try:
        return aead.decrypt(nonce, ciphertext, aad if aad else None)
    except InvalidTag as exc:
        raise DecryptionError(
            "Dekripsi gagal: kata sandi salah atau cipherteks telah diubah (verifikasi tag gagal)."
        ) from exc


# --------------------------------------------------------------------------- #
# Blob format: salt + nonce + metadata + ciphertext(+tag) dijadikan satu paket
# --------------------------------------------------------------------------- #
# Header: MAGIC(4) | VERSION(1) | algo_id(1) | kdf_id(1) | cost_param(4, big-endian)
#         | salt(16) | nonce(12)
HEADER_FMT = ">4sBBBI"
HEADER_LEN = struct.calcsize(HEADER_FMT) + SALT_LEN + NONCE_LEN


@dataclass
class EncryptResult:
    blob: bytes
    algo_name: str
    kdf_name: str
    salt_hex: str
    nonce_hex: str
    elapsed_ms: float


def encrypt_blob(plaintext: bytes, password: str, algo_id: int = ALGO_AES_GCM,
                  kdf_id: int = KDF_PBKDF2, cost_param: int | None = None) -> EncryptResult:
    if cost_param is None:
        cost_param = default_cost_for(kdf_id)

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)  # dibangkitkan acak untuk SETIAP enkripsi

    t0 = time.perf_counter()
    key = derive_key(password, salt, kdf_id, cost_param)
    ciphertext = raw_encrypt(algo_id, key, nonce, plaintext)
    elapsed = (time.perf_counter() - t0) * 1000.0

    header = struct.pack(HEADER_FMT, MAGIC, VERSION, algo_id, kdf_id, cost_param)
    blob = header + salt + nonce + ciphertext

    return EncryptResult(
        blob=blob,
        algo_name=ALGO_NAMES[algo_id],
        kdf_name=KDF_NAMES[kdf_id],
        salt_hex=salt.hex(),
        nonce_hex=nonce.hex(),
        elapsed_ms=elapsed,
    )


@dataclass
class DecryptResult:
    plaintext: bytes
    algo_name: str
    kdf_name: str
    elapsed_ms: float


def decrypt_blob(blob: bytes, password: str) -> DecryptResult:
    if len(blob) < HEADER_LEN:
        raise DecryptionError("Berkas/cipherteks tidak valid atau rusak (terlalu pendek).")

    header_fixed_len = struct.calcsize(HEADER_FMT)
    magic, version, algo_id, kdf_id, cost_param = struct.unpack(
        HEADER_FMT, blob[:header_fixed_len]
    )
    if magic != MAGIC:
        raise DecryptionError("Format tidak dikenali: bukan berkas Brangkass yang valid.")
    if version != VERSION:
        raise DecryptionError(f"Versi format tidak didukung: {version}")

    offset = header_fixed_len
    salt = blob[offset:offset + SALT_LEN]
    offset += SALT_LEN
    nonce = blob[offset:offset + NONCE_LEN]
    offset += NONCE_LEN
    ciphertext = blob[offset:]

    t0 = time.perf_counter()
    key = derive_key(password, salt, kdf_id, cost_param)
    plaintext = raw_decrypt(algo_id, key, nonce, ciphertext)  # melempar DecryptionError bila gagal
    elapsed = (time.perf_counter() - t0) * 1000.0

    return DecryptResult(
        plaintext=plaintext,
        algo_name=ALGO_NAMES[algo_id],
        kdf_name=KDF_NAMES[kdf_id],
        elapsed_ms=elapsed,
    )


def tamper_one_byte(blob: bytes) -> bytes:
    """Mengubah satu byte terakhir cipherteks (dalam blob) untuk simulasi manipulasi."""
    if len(blob) <= HEADER_LEN:
        raise ValueError("Blob terlalu pendek untuk di-tamper.")
    b = bytearray(blob)
    b[-1] ^= 0x01
    return bytes(b)


# --------------------------------------------------------------------------- #
# Metrik pengujian
# --------------------------------------------------------------------------- #
def shannon_entropy(data: bytes) -> float:
    """Entropi Shannon dalam bit/byte (maksimum 8.0 untuk data acak sempurna)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    entropy = 0.0
    for count in freq:
        if count == 0:
            continue
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


def byte_histogram(data: bytes) -> list[int]:
    """Frekuensi kemunculan tiap nilai byte 0..255."""
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    return freq


def hamming_distance_bits(a: bytes, b: bytes) -> int:
    """Jumlah bit yang berbeda antara dua urutan byte (harus sama panjang)."""
    if len(a) != len(b):
        raise ValueError("Panjang data harus sama untuk menghitung avalanche effect.")
    diff_bits = 0
    for x, y in zip(a, b):
        diff_bits += bin(x ^ y).count("1")
    return diff_bits


def flip_one_bit(data: bytes, byte_index: int = 0, bit_index: int = 0) -> bytes:
    b = bytearray(data)
    b[byte_index] ^= (1 << bit_index)
    return bytes(b)


TAG_LEN = 16  # panjang authentication tag AEAD (GCM & Poly1305), dalam byte


def avalanche_effect(algo_id: int, key: bytes, nonce: bytes, plaintext: bytes,
                      mode: str = "plaintext") -> dict:
    """Menghitung persentase bit cipherteks yang berubah bila SATU bit input diubah.

    mode="plaintext" -> membalik satu bit plainteks, kunci & nonce tetap sama
    mode="key"       -> membalik satu bit kunci, plainteks & nonce tetap sama
    Nonce SENGAJA dibuat tetap khusus untuk pengujian ini agar perbedaan yang
    terukur murni berasal dari difusi algoritma, bukan dari nonce acak.

    CATATAN ANALISIS PENTING (untuk laporan):
    AES-GCM dan ChaCha20-Poly1305 adalah mode STREAM (berbasis CTR / counter),
    bukan mode blok berantai seperti CBC. Artinya badan cipherteks dihasilkan
    dari XOR plainteks dengan keystream, sehingga membalik 1 bit plainteks
    HANYA membalik 1 bit yang bersesuaian pada badan cipherteks (tidak
    menyebar/avalanche di badan cipherteks seperti pada cipher blok klasik).
    Difusi yang sesungguhnya terjadi pada AUTHENTICATION TAG (GHASH/Poly1305
    mengubah nyaris seluruh bit tag, idealnya mendekati 50%). Karena itu
    fungsi ini melaporkan persentase secara terpisah: badan cipherteks, tag,
    dan gabungan keduanya - agar hasil dapat dianalisis dan diinterpretasikan
    dengan benar sesuai karakteristik mode operasi yang digunakan.
    """
    ct1 = raw_encrypt(algo_id, key, nonce, plaintext)

    if mode == "plaintext":
        modified_pt = flip_one_bit(plaintext, 0, 0)
        ct2 = raw_encrypt(algo_id, key, nonce, modified_pt)
    elif mode == "key":
        modified_key = flip_one_bit(key, 0, 0)
        ct2 = raw_encrypt(algo_id, modified_key, nonce, plaintext)
    else:
        raise ValueError("mode harus 'plaintext' atau 'key'")

    body1, tag1 = ct1[:-TAG_LEN], ct1[-TAG_LEN:]
    body2, tag2 = ct2[:-TAG_LEN], ct2[-TAG_LEN:]

    total_bits = len(ct1) * 8
    body_bits = len(body1) * 8
    tag_bits = len(tag1) * 8

    diff_total = hamming_distance_bits(ct1, ct2)
    diff_body = hamming_distance_bits(body1, body2) if body_bits else 0
    diff_tag = hamming_distance_bits(tag1, tag2)

    def pct(diff, total):
        return round((diff / total) * 100.0, 3) if total else 0.0

    return {
        "mode": mode,
        "total_bits": total_bits,
        "diff_bits": diff_total,
        "percent_changed": pct(diff_total, total_bits),
        "body_bits": body_bits,
        "body_diff_bits": diff_body,
        "body_percent_changed": pct(diff_body, body_bits),
        "tag_bits": tag_bits,
        "tag_diff_bits": diff_tag,
        "tag_percent_changed": pct(diff_tag, tag_bits),
        "note": (
            "AES-GCM/ChaCha20-Poly1305 adalah mode stream: badan cipherteks hanya "
            "berubah pada posisi bit yang difliip (tidak avalanche), sedangkan "
            "authentication tag berubah signifikan (idealnya ~50%). Ini perilaku "
            "yang benar, bukan kelemahan implementasi."
        ),
    }


def benchmark_sizes(algo_id: int, kdf_id: int, password: str,
                     sizes_bytes: list[int]) -> list[dict]:
    """Mengukur waktu enkripsi & dekripsi untuk beberapa ukuran data (mis. 1KB/1MB/10MB)."""
    results = []
    for size in sizes_bytes:
        data = os.urandom(size)
        enc = encrypt_blob(data, password, algo_id=algo_id, kdf_id=kdf_id)
        t0 = time.perf_counter()
        dec = decrypt_blob(enc.blob, password)
        dec_elapsed = (time.perf_counter() - t0) * 1000.0
        assert dec.plaintext == data
        results.append({
            "size_bytes": size,
            "size_label": human_size(size),
            "encrypt_ms": round(enc.elapsed_ms, 3),
            "decrypt_ms": round(dec_elapsed, 3),
        })
    return results


def human_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 ** 2:
        return f"{n / 1024:.0f} KB"
    return f"{n / (1024 ** 2):.0f} MB"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
