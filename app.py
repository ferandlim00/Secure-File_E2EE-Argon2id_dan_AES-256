import os
from flask import Flask, render_template

app = Flask(__name__)

# ── Satu-satunya route: sajikan halaman utama ─────────────────────────
# Semua proses kriptografi kini terjadi 100% di browser pengguna.
# Server ini hanya bertugas menyajikan file HTML/CSS/JS.
@app.route('/')
def index():
    return render_template('index.html')

# ═══════════════════════════════════════════════════════════
if __name__ == '__main__':
    print('=== SecureFile Encryptor (E2EE Mode) ===')
    print('    Argon2id + AES-256-GCM')
    print('    http://localhost:5000')
    app.run(debug=True, host='0.0.0.0', port=5000)
