"""
app.py
======
Brangkass - Aplikasi Brankas Berkas Pribadi Terenkripsi (AES-256-GCM)
Topik A - Tugas Proyek Aplikasi Kriptografi, Keamanan Informasi, UNSIL.

Menjalankan:
    pip install -r requirements.txt
    python app.py
Lalu buka http://127.0.0.1:5000
"""

from __future__ import annotations

import base64
import io
import os
from functools import wraps

from flask import Flask, jsonify, render_template, request, send_file

import crypto_utils as cu
import jwt_utils

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # 64 MB batas unggah

# Kunci rahasia server untuk menandatangani JWT (fitur pengayaan API RESTful).
# Pada produksi nyata, ambil dari environment variable, JANGAN ditulis di kode.
JWT_SECRET = os.environ.get("BRANGKAS_JWT_SECRET") or jwt_utils.generate_secret()

# Kredensial demo untuk mendapatkan token (khusus demo lokal / UTS).
DEMO_API_KEY = os.environ.get("BRANGKAS_API_KEY", "demo-client")
DEMO_API_SECRET = os.environ.get("BRANGKAS_API_SECRET", "demo-secret-ubah-ini")


def _algo_id_from_name(name: str) -> int:
    mapping = {"aes-gcm": cu.ALGO_AES_GCM, "chacha20": cu.ALGO_CHACHA20_POLY1305}
    if name not in mapping:
        raise ValueError("Algoritma tidak dikenal. Pilih 'aes-gcm' atau 'chacha20'.")
    return mapping[name]


def _kdf_id_from_name(name: str) -> int:
    mapping = {"pbkdf2": cu.KDF_PBKDF2, "scrypt": cu.KDF_SCRYPT, "argon2": cu.KDF_ARGON2ID}
    if name not in mapping:
        raise ValueError("KDF tidak dikenal. Pilih 'pbkdf2', 'scrypt', atau 'argon2'.")
    return mapping[name]


# --------------------------------------------------------------------------- #
# Halaman web
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    return render_template("index.html")


# --------------------------------------------------------------------------- #
# API: enkripsi/dekripsi TEKS
# --------------------------------------------------------------------------- #
@app.post("/api/encrypt-text")
def api_encrypt_text():
    data = request.get_json(force=True)
    plaintext = data.get("plaintext", "")
    password = data.get("password", "")
    algo = data.get("algorithm", "aes-gcm")
    kdf = data.get("kdf", "pbkdf2")

    if not plaintext or not password:
        return jsonify({"error": "Teks dan kata sandi wajib diisi."}), 400

    try:
        algo_id = _algo_id_from_name(algo)
        kdf_id = _kdf_id_from_name(kdf)
        result = cu.encrypt_blob(plaintext.encode("utf-8"), password, algo_id, kdf_id)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 400

    return jsonify({
        "ciphertext_base64": base64.b64encode(result.blob).decode(),
        "ciphertext_hex": result.blob.hex(),
        "algorithm": result.algo_name,
        "kdf": result.kdf_name,
        "salt_hex": result.salt_hex,
        "nonce_hex": result.nonce_hex,
        "elapsed_ms": round(result.elapsed_ms, 3),
    })


@app.post("/api/decrypt-text")
def api_decrypt_text():
    data = request.get_json(force=True)
    password = data.get("password", "")
    encoding = data.get("encoding", "base64")
    ciphertext_str = data.get("ciphertext", "")

    if not ciphertext_str or not password:
        return jsonify({"error": "Cipherteks dan kata sandi wajib diisi."}), 400

    try:
        blob = base64.b64decode(ciphertext_str) if encoding == "base64" else bytes.fromhex(ciphertext_str)
        result = cu.decrypt_blob(blob, password)
    except cu.DecryptionError as exc:
        return jsonify({"error": str(exc)}), 401
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"Gagal memproses cipherteks: {exc}"}), 400

    return jsonify({
        "plaintext": result.plaintext.decode("utf-8", errors="replace"),
        "algorithm": result.algo_name,
        "kdf": result.kdf_name,
        "elapsed_ms": round(result.elapsed_ms, 3),
    })


# --------------------------------------------------------------------------- #
# API: enkripsi/dekripsi BERKAS
# --------------------------------------------------------------------------- #
@app.post("/api/encrypt-file")
def api_encrypt_file():
    f = request.files.get("file")
    password = request.form.get("password", "")
    algo = request.form.get("algorithm", "aes-gcm")
    kdf = request.form.get("kdf", "pbkdf2")

    if not f or not password:
        return jsonify({"error": "Berkas dan kata sandi wajib diisi."}), 400

    try:
        algo_id = _algo_id_from_name(algo)
        kdf_id = _kdf_id_from_name(kdf)
        raw = f.read()
        result = cu.encrypt_blob(raw, password, algo_id, kdf_id)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 400

    out_name = f.filename + ".brks"
    response = send_file(
        io.BytesIO(result.blob),
        as_attachment=True,
        download_name=out_name,
        mimetype="application/octet-stream",
    )
    response.headers["X-Elapsed-Ms"] = f"{result.elapsed_ms:.3f}"
    response.headers["X-Input-Bytes"] = str(len(raw))
    response.headers["Access-Control-Expose-Headers"] = "X-Elapsed-Ms, X-Input-Bytes"
    return response


@app.post("/api/decrypt-file")
def api_decrypt_file():
    f = request.files.get("file")
    password = request.form.get("password", "")

    if not f or not password:
        return jsonify({"error": "Berkas dan kata sandi wajib diisi."}), 400

    try:
        blob = f.read()
        result = cu.decrypt_blob(blob, password)
    except cu.DecryptionError as exc:
        return jsonify({"error": str(exc)}), 401
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"Gagal memproses berkas: {exc}"}), 400

    out_name = f.filename[:-5] if f.filename.endswith(".brks") else f"dekripsi_{f.filename}"
    response = send_file(
        io.BytesIO(result.plaintext),
        as_attachment=True,
        download_name=out_name,
        mimetype="application/octet-stream",
    )
    response.headers["X-Elapsed-Ms"] = f"{result.elapsed_ms:.3f}"
    response.headers["X-Output-Bytes"] = str(len(result.plaintext))
    response.headers["Access-Control-Expose-Headers"] = "X-Elapsed-Ms, X-Output-Bytes"
    return response


# --------------------------------------------------------------------------- #
# API: Analisis & Pengujian (avalanche, entropi, histogram, benchmark)
# --------------------------------------------------------------------------- #
@app.post("/api/analysis/avalanche")
def api_avalanche():
    data = request.get_json(force=True)
    algo = data.get("algorithm", "aes-gcm")
    mode = data.get("mode", "plaintext")
    text = data.get("sample_text", "Contoh plainteks untuk uji avalanche effect 2026")
    password = data.get("password", "kata-sandi-uji")

    algo_id = _algo_id_from_name(algo)
    salt = os.urandom(cu.SALT_LEN)
    nonce = os.urandom(cu.NONCE_LEN)
    key = cu.derive_key(password, salt, cu.KDF_PBKDF2, cu.DEFAULT_PBKDF2_ITER)

    result = cu.avalanche_effect(algo_id, key, nonce, text.encode("utf-8"), mode=mode)
    return jsonify(result)


@app.post("/api/analysis/entropy")
def api_entropy():
    data = request.get_json(force=True)
    text = data.get("sample_text", "Contoh plainteks untuk uji entropi dan histogram byte")
    password = data.get("password", "kata-sandi-uji")
    algo = data.get("algorithm", "aes-gcm")

    algo_id = _algo_id_from_name(algo)
    plaintext = text.encode("utf-8")
    enc = cu.encrypt_blob(plaintext, password, algo_id, cu.KDF_PBKDF2)

    # Histogram & entropi dihitung dari CIPHERTEKS murni (tanpa header/salt/nonce)
    ct_only = enc.blob[cu.HEADER_LEN:]

    return jsonify({
        "plaintext_entropy": round(cu.shannon_entropy(plaintext), 4),
        "ciphertext_entropy": round(cu.shannon_entropy(ct_only), 4),
        "plaintext_histogram": cu.byte_histogram(plaintext),
        "ciphertext_histogram": cu.byte_histogram(ct_only),
    })


@app.post("/api/analysis/benchmark")
def api_benchmark():
    data = request.get_json(force=True)
    algo = data.get("algorithm", "aes-gcm")
    kdf = data.get("kdf", "pbkdf2")
    password = data.get("password", "kata-sandi-uji")

    algo_id = _algo_id_from_name(algo)
    kdf_id = _kdf_id_from_name(kdf)

    sizes = [1 * 1024, 1 * 1024 * 1024, 10 * 1024 * 1024]  # 1 KB, 1 MB, 10 MB
    results = cu.benchmark_sizes(algo_id, kdf_id, password, sizes)
    return jsonify({"algorithm": cu.ALGO_NAMES[algo_id], "results": results})


@app.post("/api/analysis/tamper-test")
def api_tamper_test():
    """Menguji penolakan dekripsi saat kata sandi salah / cipherteks diubah."""
    data = request.get_json(force=True)
    text = data.get("sample_text", "Pesan rahasia untuk uji ketahanan")
    password = data.get("password", "kata-sandi-benar")
    wrong_password = data.get("wrong_password", "kata-sandi-salah")
    algo = data.get("algorithm", "aes-gcm")

    algo_id = _algo_id_from_name(algo)
    enc = cu.encrypt_blob(text.encode("utf-8"), password, algo_id, cu.KDF_PBKDF2)

    outcomes = {}

    # 1) Kata sandi benar -> harus berhasil
    try:
        cu.decrypt_blob(enc.blob, password)
        outcomes["correct_password"] = "berhasil"
    except cu.DecryptionError:
        outcomes["correct_password"] = "gagal (tidak seharusnya)"

    # 2) Kata sandi salah -> harus ditolak
    try:
        cu.decrypt_blob(enc.blob, wrong_password)
        outcomes["wrong_password"] = "berhasil (SEHARUSNYA GAGAL!)"
    except cu.DecryptionError:
        outcomes["wrong_password"] = "ditolak sesuai harapan"

    # 3) Cipherteks diubah satu byte -> harus ditolak
    tampered = cu.tamper_one_byte(enc.blob)
    try:
        cu.decrypt_blob(tampered, password)
        outcomes["tampered_ciphertext"] = "berhasil (SEHARUSNYA GAGAL!)"
    except cu.DecryptionError:
        outcomes["tampered_ciphertext"] = "ditolak sesuai harapan"

    return jsonify(outcomes)


# --------------------------------------------------------------------------- #
# API RESTful diamankan JWT HMAC-SHA512 (Fitur Pengayaan)
# --------------------------------------------------------------------------- #
def require_jwt(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Header Authorization: Bearer <token> wajib disertakan."}), 401
        token = auth.split(" ", 1)[1]
        try:
            claims = jwt_utils.verify_token(JWT_SECRET, token)
        except jwt_utils.TokenError as exc:
            return jsonify({"error": str(exc)}), 401
        request.jwt_claims = claims
        return fn(*args, **kwargs)
    return wrapper


@app.post("/api/v1/token")
def api_v1_token():
    """Menukar API key/secret demo dengan JWT HS512 (masa berlaku 1 jam)."""
    data = request.get_json(force=True)
    api_key = data.get("api_key", "")
    api_secret = data.get("api_secret", "")

    if api_key != DEMO_API_KEY or api_secret != DEMO_API_SECRET:
        return jsonify({"error": "API key atau secret tidak valid."}), 401

    token = jwt_utils.create_token(JWT_SECRET, {"sub": api_key}, expires_in_seconds=3600)
    return jsonify({"access_token": token, "token_type": "Bearer", "expires_in": 3600})


@app.post("/api/v1/encrypt")
@require_jwt
def api_v1_encrypt():
    data = request.get_json(force=True)
    plaintext = data.get("plaintext", "")
    password = data.get("password", "")
    algo = data.get("algorithm", "aes-gcm")

    if not plaintext or not password:
        return jsonify({"error": "plaintext dan password wajib diisi."}), 400

    algo_id = _algo_id_from_name(algo)
    result = cu.encrypt_blob(plaintext.encode("utf-8"), password, algo_id, cu.KDF_PBKDF2)
    return jsonify({
        "ciphertext_base64": base64.b64encode(result.blob).decode(),
        "algorithm": result.algo_name,
        "client": request.jwt_claims.get("sub"),
    })


@app.post("/api/v1/decrypt")
@require_jwt
def api_v1_decrypt():
    data = request.get_json(force=True)
    password = data.get("password", "")
    ciphertext_b64 = data.get("ciphertext_base64", "")

    if not ciphertext_b64 or not password:
        return jsonify({"error": "ciphertext_base64 dan password wajib diisi."}), 400

    try:
        blob = base64.b64decode(ciphertext_b64)
        result = cu.decrypt_blob(blob, password)
    except cu.DecryptionError as exc:
        return jsonify({"error": str(exc)}), 401

    return jsonify({
        "plaintext": result.plaintext.decode("utf-8", errors="replace"),
        "client": request.jwt_claims.get("sub"),
    })


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
