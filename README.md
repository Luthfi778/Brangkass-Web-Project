🔐 Brangkass — Aplikasi web (Flask/Python) untuk mengenkripsi & mendekripsi teks maupun berkas menggunakan AES-256-GCM dan ChaCha20-Poly1305. Dilengkapi derivasi kunci PBKDF2/scrypt/Argon2id, analisis avalanche effect, entropi, benchmark performa, dan REST API aman dengan JWT HMAC-SHA512.

---

## 1. Daftar Isi

- [Fitur](#2-fitur)
- [Arsitektur & Format Data](#3-arsitektur--format-data)
- [Instalasi](#4-instalasi)
- [Menjalankan Aplikasi](#5-menjalankan-aplikasi)
- [Cara Penggunaan (Web UI)](#6-cara-penggunaan-web-ui)
- [API RESTful (Fitur Pengayaan)](#7-api-restful-fitur-pengayaan)
- [Menjalankan Unit Test](#8-menjalankan-unit-test)
- [Panduan Pengujian untuk Laporan](#9-panduan-pengujian-untuk-laporan)
- [Skenario Demo UTS](#10-skenario-demo-uts)
- [Catatan Keamanan](#11-catatan-keamanan)
- [Struktur Proyek](#12-struktur-proyek)
- [Penggunaan Bantuan AI](#13-penggunaan-bantuan-ai)

---

## 2. Fitur

### Fitur wajib (sesuai spesifikasi Topik A)

| Fitur                                                                         | Status | Keterangan                     |
| ----------------------------------------------------------------------------- | ------ | ------------------------------ |
| Enkripsi simetri modern (AES-256-GCM / ChaCha20-Poly1305) untuk teks & berkas | ✅     | `crypto_utils.py`              |
| Kunci diturunkan dari kata sandi (PBKDF2 / scrypt / Argon2id) + salt acak     | ✅     | `derive_key()`                 |
| IV/nonce acak per-enkripsi, disimpan bersama cipherteks                       | ✅     | `os.urandom(12)` per panggilan |
| Cipherteks ditampilkan & dapat disalin (Base64/Hex)                           | ✅     | Tab "Teks"                     |
| Penolakan dekripsi bila kata sandi salah / cipherteks diubah                  | ✅     | `DecryptionError` (HTTP 401)   |

### Pengujian wajib

| Pengujian                                                       | Endpoint / Lokasi                                            |
| --------------------------------------------------------------- | ------------------------------------------------------------ |
| Kebenaran dekripsi (≥10 kasus, termasuk gambar & PDF)           | `tests/test_crypto.py` + tab "Berkas"                        |
| Waktu enkripsi/dekripsi untuk 1 KB, 1 MB, 10 MB                 | `POST /api/analysis/benchmark`                               |
| Avalanche effect                                                | `POST /api/analysis/avalanche` (lihat catatan penting di §9) |
| Entropi & histogram byte (cipherteks vs plainteks)              | `POST /api/analysis/entropy`                                 |
| Perbandingan ≥2 algoritma modern (AES-GCM vs ChaCha20-Poly1305) | `POST /api/analysis/compare`                                 |

### Fitur pengayaan (dipilih: **API RESTful aman dengan JWT HMAC-SHA512**)

- `POST /api/v1/token` — menukar API key/secret dengan token JWT (HS512)
- `POST /api/v1/encrypt`, `POST /api/v1/decrypt` — dilindungi `Authorization: Bearer <token>`
- Selaras dengan riset dosen pengampu (Rahmatulloh dkk., 2018 — JWT HMAC-SHA512).

Dua fitur pengayaan lain (enkripsi hibrida RSA-OAEP/ECDH, visualisasi mode ECB vs aman)
dapat ditambahkan sebagai pengembangan lanjutan bila ingin nilai tambahan lebih tinggi —
lihat bagian "Pengembangan Lanjutan" di akhir dokumen ini.

---

## 3. Arsitektur & Format Data

```
Kata Sandi ──► KDF (PBKDF2/scrypt/Argon2id) + Salt acak (16B) ──► Kunci 256-bit
                                                                       │
Plainteks ──► AEAD Encrypt (AES-256-GCM / ChaCha20-Poly1305) ◄── Nonce acak (12B)
                                                                       │
                                                                       ▼
                                                        Cipherteks + Auth Tag (16B)
```

**Format blob `.brks`** (biner, dipakai untuk teks maupun berkas):

```
[MAGIC "BRKS" (4B)] [versi (1B)] [algo_id (1B)] [kdf_id (1B)] [cost_param (4B)]
[salt (16B)] [nonce (12B)] [ciphertext || auth_tag (N+16 B)]
```

Semua metadata yang dibutuhkan untuk dekripsi (algoritma, KDF, parameter biaya,
salt, nonce) disimpan di dalam blob itu sendiri — sehingga cukup satu berkas
`.brks` + kata sandi untuk memulihkan data asli, tanpa konfigurasi tambahan.

---

## 4. Instalasi

### Prasyarat

- Python 3.10 atau lebih baru
- pip

### Langkah instalasi

```bash
# 1. Clone / salin proyek ini, lalu masuk ke direktorinya
cd brangkas

# 2. (Disarankan) buat virtual environment
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 3. Instal seluruh dependensi
pip install -r requirements.txt
```

Jika muncul error terkait `argon2-cffi` pada sistem tertentu (butuh compiler C),
Argon2id bisa dilewati — aplikasi tetap berjalan normal dengan PBKDF2/scrypt saja.

---

## 5. Menjalankan Aplikasi

```bash
python app.py
```

Lalu buka browser ke:

```
http://127.0.0.1:5000
```

Untuk mengubah kredensial demo API JWT (opsional), set environment variable
sebelum menjalankan:

```bash
export BRANGKAS_API_KEY="klien-anda"
export BRANGKAS_API_SECRET="rahasia-yang-kuat"
python app.py
```

---

## 6. Cara Penggunaan (Web UI)

Aplikasi memiliki 5 tab:

1. **Teks** — enkripsi/dekripsi pesan teks langsung, hasil bisa disalin dalam Base64/Hex.
2. **Berkas** — unggah berkas apa pun (PDF, gambar, dll.) untuk dienkripsi menjadi `.brks`,
   dan sebaliknya, unggah `.brks` untuk didekripsi kembali ke bentuk asli.
3. **Analisis & Pengujian** — menjalankan seluruh pengujian wajib (tamper test, avalanche
   effect, entropi + histogram byte, benchmark waktu) langsung dari browser.
4. **Perbandingan Algoritma** — grafik perbandingan waktu AES-256-GCM vs ChaCha20-Poly1305.
5. **API (JWT)** — demo interaktif fitur pengayaan API RESTful yang diamankan JWT HS512.

---

## 7. API RESTful (Fitur Pengayaan)

Contoh pemakaian dengan `curl`:

```bash
# 1. Ambil token JWT
curl -X POST http://127.0.0.1:5000/api/v1/token \
  -H "Content-Type: application/json" \
  -d '{"api_key":"demo-client","api_secret":"demo-secret-ubah-ini"}'
# -> {"access_token": "...", "token_type": "Bearer", "expires_in": 3600}

# 2. Enkripsi teks memakai token
curl -X POST http://127.0.0.1:5000/api/v1/encrypt \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN_DARI_LANGKAH_1>" \
  -d '{"plaintext":"pesan rahasia","password":"katasandi","algorithm":"aes-gcm"}'

# 3. Dekripsi kembali
curl -X POST http://127.0.0.1:5000/api/v1/decrypt \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <TOKEN_DARI_LANGKAH_1>" \
  -d '{"ciphertext_base64":"<HASIL_DARI_LANGKAH_2>","password":"katasandi"}'
```

Tanpa token yang valid, kedua endpoint `/api/v1/*` akan menolak permintaan dengan `HTTP 401`.

---

## 8. Menjalankan Unit Test

Sesuai ketentuan (minimal 5 unit test untuk fungsi inti), tersedia **11 test**
mencakup roundtrip AES-GCM & ChaCha20-Poly1305, penolakan kata sandi salah,
deteksi tamper, keacakan nonce/salt, avalanche effect, entropi, dan validasi header.

```bash
pip install pytest   # sudah termasuk di requirements.txt
pytest tests/ -v
```

Hasil yang diharapkan: seluruh test `PASSED`.

---

## 9. Panduan Pengujian untuk Laporan

Semua pengujian wajib sudah tersedia sebagai endpoint/tab di aplikasi, tinggal
dijalankan dari UI dan hasilnya di-screenshot/disalin ke laporan serta file Excel:

- **Kebenaran dekripsi**: uji minimal 10 berkas berbeda (campuran teks, gambar, PDF)
  lewat tab "Berkas", catat hasil berhasil/gagal pada tabel di laporan.
- **Waktu proses (1 KB/1 MB/10 MB)**: tab "Analisis" → "Benchmark Waktu".
- **Avalanche effect**: tab "Analisis" → bagian ini. **Penting untuk dianalisis di
  laporan**: karena AES-GCM dan ChaCha20-Poly1305 adalah mode _stream_ (berbasis
  counter), membalik 1 bit plainteks hanya mengubah 1 bit yang bersesuaian pada
  _badan_ cipherteks (bukan menyebar seperti cipher blok berantai/CBC klasik).
  Difusi sesungguhnya terlihat pada **authentication tag**, yang berubah signifikan
  (idealnya mendekati 50%). Aplikasi ini secara eksplisit memisahkan dan melaporkan
  ketiga angka (badan, tag, gabungan) agar dapat dianalisis dan diinterpretasikan
  dengan tepat — ini adalah temuan yang benar secara kriptografis, bukan kekurangan.
- **Entropi & histogram byte**: tab "Analisis" → grafik histogram plainteks vs
  cipherteks; cipherteks yang baik akan tampak rata (mendekati distribusi seragam)
  dengan entropi mendekati 8 bit/byte.
- **Perbandingan algoritma**: tab "Perbandingan Algoritma".
- **Data uji untuk file Excel (XLSX)**: seluruh endpoint `/api/analysis/*`
  mengembalikan JSON — bisa disalin langsung ke Excel, atau ditulis skrip kecil
  memakai `requests` + `openpyxl`/`pandas` untuk otomatisasi pengumpulan tabel.

---

## 10. Skenario Demo UTS

Ikuti urutan berikut agar sesuai skenario wajib pada spesifikasi tugas:

1. Buka tab **Berkas**, unggah sebuah PDF, isi kata sandi, klik **Enkripsi & Unduh**.
2. Tunjukkan isi cipherteks (buka `.brks` di editor hex/teks — terlihat acak).
3. Unggah `.brks` tersebut ke kolom dekripsi dengan kata sandi **benar** → PDF pulih.
4. Ulangi dengan kata sandi **salah** → aplikasi menampilkan pesan penolakan.
5. Ubah satu byte pada berkas `.brks` (misal dengan editor hex), coba dekripsi lagi
   dengan kata sandi benar → tetap ditolak (verifikasi tag gagal).

Langkah 4 & 5 juga bisa didemonstrasikan lebih cepat lewat tab **Analisis & Pengujian**
→ "Uji Ketahanan (Correctness & Tamper Test)", yang menjalankan ketiganya sekaligus.

---

## 11. Catatan Keamanan

- Kunci, kata sandi, dan kunci privat **tidak pernah** ditulis langsung di kode sumber.
- Semua nilai acak (salt, nonce, kunci) dibangkitkan dengan `os.urandom` (CSPRNG).
- Mode ECB dan algoritma usang (MD5, SHA-1, DES, RC4) **tidak dipakai** untuk fitur
  keamanan utama pada aplikasi ini.
- `JWT_SECRET` server dibangkitkan otomatis saat start bila tidak diset lewat
  environment variable — pada penggunaan nyata, selalu set lewat env var.
- Batas ukuran unggah diset 64 MB (`MAX_CONTENT_LENGTH`) untuk mencegah penyalahgunaan.

---

## 12. Struktur Proyek

```
brangkas/
├── app.py                  # Flask app: routing halaman & REST API
├── crypto_utils.py         # Inti kriptografi: KDF, AEAD, format blob, metrik uji
├── jwt_utils.py            # JWT HMAC-SHA512 manual (fitur pengayaan API)
├── requirements.txt
├── README.md
├── templates/
│   └── index.html          # UI web (5 tab)
├── static/
│   ├── style.css
│   └── app.js               # Logika frontend + Chart.js
└── tests/
    └── test_crypto.py      # 11 unit test (pytest)
```

---

## 13. Penggunaan Bantuan AI

Sebagian besar kode pada proyek ini (struktur aplikasi Flask, modul `crypto_utils.py`,
`jwt_utils.py`, antarmuka web, serta unit test) disusun dengan bantuan asisten AI
(Claude, Anthropic) berdasarkan spesifikasi topik yang diberikan dosen pengampu.
Seluruh anggota kelompok telah mereview, menjalankan, dan memahami cara kerja kode
sebelum pengumpulan, sesuai ketentuan integritas akademik pada Bagian 10 spesifikasi
tugas. Bagian yang **wajib ditulis sendiri oleh mahasiswa** untuk laporan akhir:
dasar teori, analisis hasil pengujian (termasuk interpretasi avalanche effect di
atas), diagram rancangan sistem, dan kesimpulan.

---

## Pengembangan Lanjutan (opsional, untuk nilai tambahan)

- **Enkripsi hibrida**: bungkus kunci sesi AES dengan RSA-OAEP (`cryptography.hazmat.primitives.asymmetric.rsa`)
  atau sepakati kunci lewat ECDH sebelum derivasi HKDF.
- **Visualisasi mode ECB vs aman**: enkripsi citra bitmap mentah dengan AES-ECB
  (hanya untuk demonstrasi edukatif, ditandai jelas sebagai contoh kelemahan) vs
  AES-GCM, lalu tampilkan pola yang muncul pada mode ECB.
