# 🔐 Brangkass — Aplikasi Brankas Berkas Pribadi Terenkripsi

Aplikasi web (Python/Flask) untuk mengenkripsi dan mendekripsi **teks maupun berkas**
(PDF, gambar, dll.) memakai algoritma kriptografi modern **AES-256-GCM** atau
**ChaCha20-Poly1305**, dengan kunci diturunkan secara aman dari kata sandi.

Dibuat untuk **Tugas Proyek Aplikasi Kriptografi — Topik A (Enkripsi Algoritma Modern)**,
mata kuliah Keamanan Informasi, Program Studi Informatika, Universitas Siliwangi.

**Nama Anggota:**
- Ginanjar Abdul Hakim (247006111159)
- Luthfi Apriliansyah (247006111165)

---

## 1. Daftar Isi

- [Fitur](#2-fitur)
- [Arsitektur & Format Data](#3-arsitektur--format-data)
- [Instalasi](#4-instalasi)
- [Menjalankan Aplikasi](#5-menjalankan-aplikasi)
- [Panduan Penggunaan Setiap Fitur](#6-panduan-penggunaan-setiap-fitur)
- [API RESTful (Fitur Pengayaan)](#7-api-restful-fitur-pengayaan)
- [Menjalankan Unit Test](#8-menjalankan-unit-test)
- [Panduan Pengujian untuk Laporan](#9-panduan-pengujian-untuk-laporan)
- [Skenario Demo UTS](#10-skenario-demo-uts)
- [Pemecahan Masalah (Troubleshooting)](#11-pemecahan-masalah-troubleshooting)
- [Catatan Keamanan](#12-catatan-keamanan)
- [Struktur Proyek](#13-struktur-proyek)
- [Penggunaan Bantuan AI](#14-penggunaan-bantuan-ai)

---

## 2. Fitur

### Tampilan
- Sidebar navigasi tetap di kiri, kanvas konten dapat dialihkan ke **mode terang / gelap**
  (tersimpan otomatis di browser lewat `localStorage`, tidak reset saat refresh).
- Kartu **"tentang aplikasi"** singkat di bagian atas setiap halaman, menjelaskan fungsi
  Brangkass beserta chip algoritma yang dipakai.
- Setiap kolom kata sandi punya tombol mata 👁 untuk menampilkan/menyembunyikan isinya.
- Berkas yang dipilih (baik untuk dienkripsi maupun hasil dekripsi) langsung ditampilkan
  pratinjaunya: thumbnail bila berupa gambar, atau ikon + nama + ukuran untuk jenis lain.

### Fitur wajib (sesuai spesifikasi Topik A)
| Fitur | Status | Keterangan |
|---|---|---|
| Enkripsi simetri modern (AES-256-GCM / ChaCha20-Poly1305) untuk teks & berkas | ✅ | `crypto_utils.py` |
| Kunci diturunkan dari kata sandi (PBKDF2 / scrypt / Argon2id) + salt acak | ✅ | `derive_key()` |
| IV/nonce acak per-enkripsi, disimpan bersama cipherteks | ✅ | `os.urandom(12)` per panggilan |
| Cipherteks ditampilkan & dapat disalin (Base64/Hex) | ✅ | Halaman "Teks" |
| Penolakan dekripsi bila kata sandi salah / cipherteks diubah | ✅ | `DecryptionError` (HTTP 401) |

### Pengujian wajib (halaman "Analisis & Pengujian")
| Pengujian | Keterangan |
|---|---|
| Kebenaran dekripsi (≥10 kasus, termasuk gambar & PDF) | `tests/test_crypto.py` + halaman "Berkas" |
| Waktu enkripsi/dekripsi untuk 1 KB, 1 MB, 10 MB | Kartu "Benchmark waktu" |
| Avalanche effect | Kartu "Avalanche effect" (lihat catatan penting di §9) |
| Entropi & histogram byte (cipherteks vs plainteks) | Kartu "Entropi & histogram byte" |
| Tombol **"Unduh semua hasil uji (.xlsx)"** | Menggabungkan semua hasil ke satu berkas Excel multi-sheet |

### Fitur pengayaan (dipilih: **API RESTful aman dengan JWT HMAC-SHA512**)
- `POST /api/v1/token` — menukar API key/secret dengan token JWT (HS512)
- `POST /api/v1/encrypt`, `POST /api/v1/decrypt` — dilindungi `Authorization: Bearer <token>`
- Selaras dengan riset dosen pengampu (Rahmatulloh dkk., 2018 — JWT HMAC-SHA512).

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

> **Catatan:** semua pustaka JavaScript (Chart.js untuk grafik, SheetJS untuk ekspor
> Excel) sudah dipaketkan langsung di `static/vendor/` dan dimuat dari server sendiri,
> **bukan** dari CDN pihak ketiga. Artinya aplikasi tetap berfungsi penuh walau
> perangkat yang menjalankannya tidak punya akses internet sama sekali (lihat §11).

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

## 6. Panduan Penggunaan Setiap Fitur

Aplikasi memiliki 4 halaman yang dapat dipilih dari sidebar kiri.

### 6.1 Halaman "Teks"
Untuk mengenkripsi atau mendekripsi pesan singkat.

**Mengenkripsi teks:**
1. Tulis pesan pada kolom "Teks / plainteks".
2. Isi "Kata sandi" (klik ikon mata 👁 bila ingin memastikan ketikannya benar).
3. Pilih "Algoritma" (AES-256-GCM atau ChaCha20-Poly1305) dan "Derivasi kunci (KDF)".
4. Klik **Enkripsi**. Hasilnya berupa cipherteks dalam format Base64 dan Hex,
   beserta waktu proses, salt, dan nonce yang dipakai. Klik "Salin Base64"/"Salin Hex"
   untuk menyalinnya.

**Mendekripsi teks:**
1. Tempel cipherteks pada kolom "Cipherteks", pilih formatnya (Base64/Hex).
2. Isi kata sandi yang sama dengan saat mengenkripsi.
3. Klik **Dekripsi**. Bila kata sandi salah atau cipherteks tidak valid, aplikasi
   akan menampilkan pesan error alih-alih data yang salah.

### 6.2 Halaman "Berkas"
Untuk mengenkripsi/mendekripsi berkas (dokumen, gambar, dll.) menjadi/dari format `.brks`.

**Mengenkripsi berkas:**
1. Klik "Choose File" dan pilih berkas — pratinjaunya (thumbnail gambar atau ikon
   generik + nama + ukuran) langsung muncul di bawah kolom unggah.
2. Isi kata sandi, pilih algoritma dan KDF.
3. Klik **Enkripsi & unduh (.brks)** — berkas terenkripsi otomatis terunduh.

**Mendekripsi berkas:**
1. Pilih berkas `.brks` yang ingin didekripsi.
2. Isi kata sandi yang sama, klik **Dekripsi & unduh**.
3. Bila berhasil, pratinjau hasilnya ditampilkan dan berkas asli otomatis terunduh.
   Bila kata sandi salah atau berkas telah diubah, muncul pesan error dan tidak ada
   berkas yang diunduh.

### 6.3 Halaman "Analisis & Pengujian"
Berisi lima kartu pengujian, masing-masing dapat dijalankan independen:

1. **Uji ketahanan (correctness & tamper test)** — isi teks contoh dan dua kata sandi
   (benar & salah), klik "Jalankan uji". Aplikasi menjalankan tiga skenario sekaligus:
   dekripsi dengan kata sandi benar (harus berhasil), dengan kata sandi salah (harus
   ditolak), dan dengan cipherteks yang sengaja diubah satu byte (harus ditolak).
2. **Avalanche effect** — pilih algoritma dan bagian yang diuji (1 bit plainteks atau
   1 bit kunci), klik "Hitung avalanche effect". Hasilnya memisahkan persentase
   perubahan pada badan cipherteks vs authentication tag (lihat §9 untuk interpretasinya).
3. **Entropi & histogram byte** — isi teks contoh, klik "Hitung entropi & histogram".
   Menampilkan nilai entropi Shannon plainteks vs cipherteks, beserta grafik histogram
   distribusi byte-nya.
4. **Benchmark waktu (1 KB/1 MB/10 MB)** — pilih algoritma & KDF, klik "Jalankan
   benchmark". Mengukur waktu enkripsi dan dekripsi pada tiga ukuran data yang berbeda
   memakai data acak internal (tanpa perlu unggah berkas).
5. **Unduh seluruh hasil uji** — setelah menjalankan satu atau lebih pengujian di atas,
   tombol ini menggabungkan semua hasil yang sudah dijalankan menjadi satu berkas Excel
   (multi-sheet), sesuai ketentuan luaran "Data Pengujian" pada spesifikasi tugas.
   Setiap kartu juga punya tombol "Unduh Excel" sendiri-sendiri.

### 6.4 Halaman "API (JWT)"
Demo interaktif fitur pengayaan API RESTful yang diamankan JWT HMAC-SHA512:
1. Klik **1. Ambil token JWT** — memakai kredensial demo bawaan (`demo-client` /
   `demo-secret-ubah-ini`) untuk mendapatkan token Bearer.
2. Isi teks dan kata sandi, klik **Enkripsi via /api/v1/encrypt** — permintaan
   dikirim dengan header `Authorization: Bearer <token>` dari langkah 1.
3. Klik **Dekripsi hasil di atas via /api/v1/decrypt** untuk memulihkan teksnya
   memakai token dan kata sandi yang sama.

Lihat §7 untuk contoh pemanggilan API ini lewat `curl`.

### 6.5 Mode Terang / Gelap
Klik tombol **"Mode gelap"/"Mode terang"** di bagian bawah sidebar untuk beralih
tema. Pilihan ini tersimpan di browser dan akan tetap dipakai saat halaman dibuka
kembali.

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

Semua pengujian wajib sudah tersedia sebagai kartu di halaman "Analisis & Pengujian",
tinggal dijalankan dan hasilnya di-screenshot/diunduh sebagai Excel untuk laporan:

- **Kebenaran dekripsi**: uji minimal 10 berkas berbeda (campuran teks, gambar, PDF)
  lewat halaman "Berkas", catat hasil berhasil/gagal pada tabel di laporan.
- **Waktu proses (1 KB/1 MB/10 MB)**: kartu "Benchmark waktu".
- **Avalanche effect**: **Penting untuk dianalisis di laporan** — karena AES-GCM dan
  ChaCha20-Poly1305 adalah mode *stream* (berbasis counter), membalik 1 bit plainteks
  hanya mengubah 1 bit yang bersesuaian pada *badan* cipherteks (bukan menyebar seperti
  cipher blok berantai/CBC klasik). Difusi sesungguhnya terlihat pada **authentication
  tag**, yang berubah signifikan (idealnya mendekati 50%). Aplikasi ini secara eksplisit
  memisahkan dan melaporkan ketiga angka (badan, tag, gabungan) agar dapat dianalisis
  dan diinterpretasikan dengan tepat — ini temuan yang benar secara kriptografis,
  bukan kekurangan.
- **Entropi & histogram byte**: grafik histogram plainteks vs cipherteks; cipherteks
  yang baik akan tampak rata (mendekati distribusi seragam) dengan entropi mendekati
  8 bit/byte pada data yang cukup besar (pada data sangat kecil, entropi maksimum
  yang bisa dicapai dibatasi oleh log₂(ukuran data dalam byte)).
- **Data uji untuk file Excel (XLSX)**: tombol "Unduh Excel" di setiap kartu, atau
  "Unduh semua hasil uji" untuk menggabungkan semuanya ke satu berkas multi-sheet.

---

## 10. Skenario Demo UTS

Ikuti urutan berikut agar sesuai skenario wajib pada spesifikasi tugas:

1. Buka halaman **Berkas**, unggah sebuah PDF, isi kata sandi, klik **Enkripsi & unduh**.
2. Tunjukkan isi cipherteks (buka `.brks` di editor hex/teks — terlihat acak).
3. Unggah `.brks` tersebut ke kolom dekripsi dengan kata sandi **benar** → berkas pulih
   (pratinjau ditampilkan bila berupa gambar).
4. Ulangi dengan kata sandi **salah** → aplikasi menampilkan pesan penolakan.
5. Ubah satu byte pada berkas `.brks` (misal dengan editor hex), coba dekripsi lagi
   dengan kata sandi benar → tetap ditolak (verifikasi tag gagal).

Langkah 4 & 5 juga bisa didemonstrasikan lebih cepat lewat halaman **Analisis &
Pengujian** → kartu "Uji ketahanan", yang menjalankan ketiganya sekaligus.

---

## 11. Pemecahan Masalah (Troubleshooting)

### "Chart is not defined" atau histogram/grafik tidak muncul
Pernah terjadi pada versi sebelumnya karena Chart.js dan SheetJS dimuat dari CDN
eksternal (`cdnjs.cloudflare.com`), yang bisa gagal dimuat bila jaringan pengguna
memblokir domain tersebut (firewall kampus/kantor, ad-blocker, dsb). **Ini sudah
diperbaiki**: kedua pustaka sekarang disertakan langsung di dalam proyek
(`static/vendor/chart.umd.min.js` dan `static/vendor/xlsx.full.min.js`) dan dimuat
dari server Flask sendiri, sehingga tidak lagi bergantung pada koneksi ke pihak
ketiga. Sebagai lapisan pengaman tambahan, bila karena suatu sebab berkas tersebut
tetap gagal dimuat, halaman "Entropi & histogram byte" akan menggambar histogram
secara manual langsung ke elemen `<canvas>` (tanpa Chart.js), dan tombol-tombol
"Unduh Excel" akan menampilkan pesan yang jelas ("Pustaka Excel gagal dimuat, coba
muat ulang halaman") alih-alih error mentah di konsol browser.

Bila error serupa masih muncul: tekan **Ctrl/Cmd+Shift+R** untuk memuat ulang
halaman tanpa cache, dan pastikan folder `static/vendor/` ikut ter-copy saat
proyek dipindahkan atau di-deploy.

### Argon2id tidak tersedia
Jika `argon2-cffi` gagal terinstal (biasanya karena tidak ada compiler C di sistem),
pilih PBKDF2 atau scrypt sebagai KDF — keduanya tidak memerlukan dependensi tambahan.

### Port 5000 sudah dipakai aplikasi lain
Jalankan dengan port berbeda, misalnya:
```bash
python -c "from app import app; app.run(port=5050)"
```

---

## 12. Catatan Keamanan

- Kunci, kata sandi, dan kunci privat **tidak pernah** ditulis langsung di kode sumber.
- Semua nilai acak (salt, nonce, kunci) dibangkitkan dengan `os.urandom` (CSPRNG).
- Mode ECB dan algoritma usang (MD5, SHA-1, DES, RC4) **tidak dipakai** untuk fitur
  keamanan utama pada aplikasi ini.
- `JWT_SECRET` server dibangkitkan otomatis saat start bila tidak diset lewat
  environment variable — pada penggunaan nyata, selalu set lewat env var.
- Batas ukuran unggah diset 64 MB (`MAX_CONTENT_LENGTH`) untuk mencegah penyalahgunaan.
- Semua aset JavaScript (Chart.js, SheetJS) dihosting sendiri, bukan dari CDN,
  sehingga tidak ada kode pihak ketiga yang dimuat langsung dari internet saat
  aplikasi dipakai secara lokal/offline.

---

## 13. Struktur Proyek

```
brangkas/
├── app.py                  # Flask app: routing halaman & REST API
├── crypto_utils.py         # Inti kriptografi: KDF, AEAD, format blob, metrik uji
├── jwt_utils.py            # JWT HMAC-SHA512 manual (fitur pengayaan API)
├── requirements.txt
├── README.md
├── templates/
│   └── index.html          # UI web (4 halaman + sidebar)
├── static/
│   ├── style.css
│   ├── app.js               # Logika frontend, tema, preview berkas, ekspor Excel
│   └── vendor/
│       ├── chart.umd.min.js     # Chart.js (di-host sendiri, bukan CDN)
│       └── xlsx.full.min.js     # SheetJS (di-host sendiri, bukan CDN)
└── tests/
    └── test_crypto.py      # 11 unit test (pytest)
```

---

## 14. Penggunaan Bantuan AI

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
