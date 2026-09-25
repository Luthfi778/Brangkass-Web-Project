"""
tests/test_crypto.py
=====================
Unit test untuk fungsi inti aplikasi Brangkass (memenuhi ketentuan minimal
5 unit test untuk fungsi enkripsi/dekripsi/verifikasi).

Jalankan dengan:
    pytest tests/ -v
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

import crypto_utils as cu


PASSWORD = "kata-sandi-uji-123"


@pytest.mark.parametrize("algo_id", [cu.ALGO_AES_GCM, cu.ALGO_CHACHA20_POLY1305])
def test_encrypt_decrypt_roundtrip_text(algo_id):
    """1. Teks yang dienkripsi harus bisa didekripsi kembali persis sama."""
    plaintext = "Halo, ini pesan rahasia! 🔐".encode("utf-8")
    result = cu.encrypt_blob(plaintext, PASSWORD, algo_id=algo_id)
    dec = cu.decrypt_blob(result.blob, PASSWORD)
    assert dec.plaintext == plaintext


@pytest.mark.parametrize("algo_id", [cu.ALGO_AES_GCM, cu.ALGO_CHACHA20_POLY1305])
def test_encrypt_decrypt_roundtrip_binary(algo_id):
    """2. Data biner (mensimulasikan gambar/PDF) harus tetap utuh setelah roundtrip."""
    plaintext = os.urandom(4096)
    result = cu.encrypt_blob(plaintext, PASSWORD, algo_id=algo_id)
    dec = cu.decrypt_blob(result.blob, PASSWORD)
    assert dec.plaintext == plaintext


def test_wrong_password_is_rejected():
    """3. Dekripsi dengan kata sandi salah harus ditolak (DecryptionError)."""
    plaintext = b"data sensitif"
    result = cu.encrypt_blob(plaintext, PASSWORD)
    with pytest.raises(cu.DecryptionError):
        cu.decrypt_blob(result.blob, "kata-sandi-yang-salah")


def test_tampered_ciphertext_is_rejected():
    """4. Cipherteks yang diubah satu byte harus gagal verifikasi tag (ditolak)."""
    plaintext = b"jangan diubah ya"
    result = cu.encrypt_blob(plaintext, PASSWORD)
    tampered = cu.tamper_one_byte(result.blob)
    with pytest.raises(cu.DecryptionError):
        cu.decrypt_blob(tampered, PASSWORD)


def test_nonce_is_random_each_time():
    """5. IV/nonce harus berbeda pada setiap proses enkripsi (walau plainteks & kunci sama)."""
    plaintext = b"pesan yang sama"
    r1 = cu.encrypt_blob(plaintext, PASSWORD)
    r2 = cu.encrypt_blob(plaintext, PASSWORD)
    assert r1.nonce_hex != r2.nonce_hex
    assert r1.salt_hex != r2.salt_hex
    # Karena nonce & salt berbeda, cipherteks pun harus berbeda meski plainteks sama
    assert r1.blob != r2.blob


def test_avalanche_effect_tag_shows_diffusion_body_does_not():
    """6. Avalanche effect pada mode AEAD stream (GCM/Poly1305):
    - Badan cipherteks TIDAK avalanche (hanya berubah pada posisi bit yang diflip),
      karena badan = plainteks XOR keystream (mode CTR-like).
    - Authentication tag HARUS menunjukkan difusi signifikan (mendekati 50%),
      karena dihitung dari GHASH/Poly1305 atas seluruh data.
    Ini adalah karakteristik yang benar dari mode stream AEAD, bukan cacat.
    """
    key = os.urandom(32)
    nonce = os.urandom(12)
    plaintext = os.urandom(256)
    result = cu.avalanche_effect(cu.ALGO_AES_GCM, key, nonce, plaintext, mode="plaintext")

    # Badan cipherteks: hanya 1 bit yang berbeda (posisi bit yang diflip)
    assert result["body_diff_bits"] == 1

    # Tag: harus menunjukkan difusi signifikan, toleransi longgar 20-80%
    assert 20.0 <= result["tag_percent_changed"] <= 80.0


def test_ciphertext_entropy_higher_than_plaintext():
    """7. Entropi cipherteks (data acak) harus jauh lebih tinggi daripada plainteks berulang."""
    plaintext = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # entropi rendah
    result = cu.encrypt_blob(plaintext, PASSWORD)
    ct_only = result.blob[cu.HEADER_LEN:]
    plain_entropy = cu.shannon_entropy(plaintext)
    cipher_entropy = cu.shannon_entropy(ct_only)
    assert cipher_entropy > plain_entropy


def test_different_kdfs_produce_different_keys():
    """8. KDF berbeda (dengan salt & cost yang sama) harus menghasilkan kunci berbeda."""
    salt = os.urandom(16)
    key_pbkdf2 = cu.derive_key(PASSWORD, salt, cu.KDF_PBKDF2, 100_000)
    key_scrypt = cu.derive_key(PASSWORD, salt, cu.KDF_SCRYPT, 2 ** 12)
    assert key_pbkdf2 != key_scrypt
    assert len(key_pbkdf2) == cu.KEY_LEN
    assert len(key_scrypt) == cu.KEY_LEN


def test_invalid_magic_header_rejected():
    """9. Blob dengan header tidak valid (bukan format Brangkass) harus ditolak."""
    garbage = os.urandom(64)
    with pytest.raises(cu.DecryptionError):
        cu.decrypt_blob(garbage, PASSWORD)
