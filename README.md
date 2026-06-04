# 🔐 SecureFile

> **Proteksi Berkas End-to-End pada Lingkungan Browser Menggunakan Kriptografi AES-256 dan Argon2**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0.0-green)](https://flask.palletsprojects.com)
[![E2EE](https://img.shields.io/badge/Encryption-E2EE-gold)](https://en.wikipedia.org/wiki/End-to-end_encryption)

---

## Tentang Proyek

**SecureFile** adalah aplikasi web enkripsi berkas berbasis browser yang mengimplementasikan **End-to-End Encryption (E2EE)** sejati. Seluruh proses kriptografi — mulai dari derivasi kunci hingga enkripsi/dekripsi — dilakukan **100% di browser pengguna** menggunakan:

- **Argon2id** (via WebAssembly) — untuk mengubah password menjadi kunci kriptografi yang kuat
- **AES-256-GCM** (via Web Crypto API) — untuk enkripsi terautentikasi

> **Server tidak pernah melihat file asli, password, maupun kunci enkripsi pengguna.**

---

## Fitur Utama

- 🔒 **Enkripsi E2EE** — semua crypto terjadi di browser, server hanya sajikan halaman
- 🔑 **Argon2id KDF** — resistensi tinggi terhadap brute-force & GPU attack (64 MB RAM / operasi)
- 🛡️ **AES-256-GCM** — enkripsi + verifikasi integritas dalam satu operasi (AEAD)
- 📁 **Semua tipe file** — dokumen, gambar, video, arsip, dan lainnya (maks. 500 MB)
- 🔍 **Encryption Inspector** — visualisasi step-by-step: Salt → Argon2id → Derived Key → IV → Auth Tag → Ciphertext
- 💪 **Password Strength Meter** — indikator kekuatan password real-time (5 level)
- 🖱️ **Drag & Drop** — seret berkas langsung ke zona upload
- 📱 **Responsive** — berfungsi di desktop dan smartphone
- 🚫 **Tanpa Database** — stateless, tidak ada data yang disimpan di server

---

## Cara Kerja (E2EE Flow)

```
ENKRIPSI
────────────────────────────────────────────────────────────
Browser                                         Server
  │                                               │
  ├─ 1. Baca file → Uint8Array                    │
  ├─ 2. Generate Salt (16B) + IV (12B) acak       │
  ├─ 3. Argon2id(password, salt) → Key 32B [WASM] │
  ├─ 4. AES-256-GCM.encrypt(file, key, iv)        │
  ├─ 5. Bangun file .enc (binary format)           │
  └─ 6. URL.createObjectURL → Download langsung   │
                                                  │
                              Hanya serve ────────┘
                              HTML/CSS/JS

DEKRIPSI
────────────────────────────────────────────────────────────
Browser
  ├─ 1. Baca file .enc → parse header (salt, iv, filename)
  ├─ 2. Argon2id(password, salt) → Key 32B [WASM]
  ├─ 3. AES-256-GCM.decrypt(ciphertext+tag, key, iv)
  │       ├─ GAGAL → password salah / file dimodifikasi
  │       └─ SUKSES → file bytes asli
  └─ 4. URL.createObjectURL → Download file asli
```

---

## Format File `.enc`

Setiap berkas terenkripsi menggunakan format biner kustom. Semua metadata yang dibutuhkan untuk dekripsi tersimpan di dalam file itu sendiri — tidak memerlukan database.

```
┌──────────────────────────────────────────────────────────────┐
│  Offset  │  Ukuran  │  Field       │  Keterangan             │
├──────────────────────────────────────────────────────────────┤
│  0       │  8 byte  │  MAGIC       │  "SECFILE\x01"          │
│  8       │  16 byte │  SALT        │  Argon2id salt (random) │
│  24      │  12 byte │  IV          │  AES-GCM nonce (random) │
│  36      │  2 byte  │  FNAME_LEN   │  Panjang nama file      │
│  38      │  N byte  │  FILENAME    │  Nama file asli (UTF-8) │
│  38+N    │  M byte  │  CIPHERTEXT  │  Data + Auth Tag (16B)  │
└──────────────────────────────────────────────────────────────┘
```

---

## Parameter Kriptografi

| Parameter | Nilai | Keterangan |
|-----------|-------|-----------|
| Algoritma KDF | Argon2id | Gabungan Argon2i + Argon2d |
| `time_cost` | 3 | Iterasi komputasi |
| `memory_cost` | 65536 KB (64 MB) | Memori RAM per operasi |
| `parallelism` | 4 | Thread paralel |
| `hash_len` | 32 byte (256-bit) | Panjang derived key |
| Algoritma Enkripsi | AES-256-GCM | Authenticated Encryption (AEAD) |
| Key size | 256-bit | |
| IV / Nonce | 12 byte (96-bit) | Per-enkripsi random |
| Auth Tag | 16 byte (128-bit) | Verifikasi integritas |

---

## Teknologi

| Layer | Teknologi |
|-------|-----------|
| Backend | Python 3.8+ · Flask 3.0.0 |
| Frontend | HTML5 · Vanilla CSS · Vanilla JS (ES6+) |
| KDF (browser) | [argon2-browser](https://github.com/antelle/argon2-browser) v1.18.0 — WebAssembly |
| Enkripsi (browser) | Web Crypto API — built-in semua browser modern |
| Font | Google Fonts — Outfit + JetBrains Mono |

---

## Instalasi & Menjalankan

### Persyaratan

- Python 3.8 atau lebih baru
- Browser modern: Chrome 80+, Firefox 75+, Safari 14+, Edge 80+
- Koneksi internet (untuk memuat library argon2-browser via CDN saat pertama kali)

### Langkah

```bash
# 1. Clone atau masuk ke folder proyek
cd "SecureFile"

# 2. Install dependensi Python
pip install -r requirements.txt

# 3. Jalankan server
python app.py
```

### Akses Aplikasi

| Platform | URL |
|----------|-----|
| Browser Desktop | `http://localhost:5000` |
| Browser Mobile (WiFi sama) | `http://<IP-LAN>:5000` |
| Akses publik via ngrok | `ngrok http 5000` |

---

## Cara Menggunakan

### Enkripsi File

1. Buka tab **"Enkripsi File"**
2. Seret file ke zona upload, atau klik untuk membuka file picker
3. Masukkan **Secret Key** (gunakan password yang kuat — lihat indikator kekuatan)
4. Klik tombol **"Enkripsi File"**
5. Tunggu proses Argon2id + AES-256-GCM selesai (~1–3 detik)
6. Klik **"Unduh File"** untuk menyimpan file `.enc`

### Dekripsi File

1. Buka tab **"Dekripsi File"**
2. Pilih file `.enc` yang ingin didekripsi
3. Masukkan **Secret Key yang sama** saat enkripsi
4. Klik tombol **"Dekripsi File"**
5. Jika password benar, badge **"Auth Tag Terverifikasi"** akan muncul
6. Klik **"Unduh File"** untuk mendapatkan file asli

> ⚠️ **Penting:** Secret Key tidak dapat dipulihkan jika lupa. Tidak ada mekanisme reset karena server tidak menyimpan apapun.

---

## Struktur Proyek

```
SecureFile/
├── app.py                  # Flask server — hanya route GET /
├── requirements.txt        # Dependensi Python (hanya Flask)
│
├── templates/
│   └── index.html          # Single Page App — dua tab enkripsi/dekripsi
│
└── static/
    ├── css/
    │   └── style.css       # Tema Gold & Gray, animasi, responsive
    └── js/
        └── app.js          # Seluruh logika E2EE: Argon2id + AES-256-GCM
```

> **Catatan:** `app.py` hanya berisi 19 baris karena seluruh logika kriptografi telah dipindahkan ke browser.

---

## Analisis Keamanan

| Ancaman | Mitigasi |
|---------|---------|
| Brute-force password | Argon2id: setiap percobaan butuh ~2 detik + 64 MB RAM |
| Rainbow table | Salt 16 byte acak per enkripsi |
| File tampering | Auth Tag AES-GCM mendeteksi modifikasi sekecil apapun |
| Nonce reuse | IV 12 byte di-generate dengan `crypto.getRandomValues()` per enkripsi |
| Server compromise | Server tidak memiliki file, password, atau kunci — tidak ada yang bisa dicuri |
| Man-in-the-Middle | File sudah terenkripsi sepenuhnya sebelum meninggalkan browser |

---

## Jaminan Keamanan

```
✅ Kerahasiaan  — Tanpa kunci yang benar, ciphertext tidak dapat dipecahkan
✅ Integritas   — Auth Tag AES-GCM mendeteksi perubahan sekecil apapun
✅ E2EE Sejati  — Server tidak pernah memegang plaintext atau password
✅ Salt Unik    — Dua enkripsi file yang sama menghasilkan .enc yang berbeda
✅ IV Unik      — Tidak ada risiko nonce reuse attack
```

---

## Keterbatasan

- Ukuran file maksimal **500 MB** (diproses di RAM browser)
- Memerlukan koneksi internet saat pertama kali (untuk memuat CDN argon2-browser ~1.5 MB)
- Tidak mendukung enkripsi batch (banyak file sekaligus)
- Tidak ada manajemen kunci — pengguna bertanggung jawab menyimpan secret key

---

## Lisensi

Proyek ini dibuat untuk keperluan akademis — mata kuliah **Keamanan Komputer**.

---

*SecureFile — Argon2id · AES-256-GCM · E2EE · Client-Side Only*
#
