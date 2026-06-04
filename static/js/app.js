// =====================================================================
// SecureFile Encryptor — app.js (E2EE Client-Side Mode)
// Semua kriptografi terjadi 100% di browser:
//   - Argon2id  via argon2-browser (WebAssembly)
//   - AES-256-GCM via Web Crypto API (built-in browser)
// Server tidak pernah melihat file asli, password, atau kunci enkripsi.
// =====================================================================

// ── Konstanta Format File .enc ─────────────────────────────────────────
// Harus sama persis dengan format yang dipakai versi server-side
// agar file lama tetap kompatibel
const MAGIC        = new Uint8Array([83, 69, 67, 70, 73, 76, 69, 1]); // "SECFILE\x01"
const SALT_LEN     = 16;   // 16 byte = 128 bit
const IV_LEN       = 12;   // 12 byte = 96 bit (rekomendasi GCM)
const AUTH_TAG_LEN = 16;   // 16 byte (append otomatis oleh AES-GCM)

// ── Parameter Argon2id (sama dengan versi server) ─────────────────────
const ARGON2_TIME_COST   = 3;
const ARGON2_MEMORY_COST = 65536;   // 64 MB
const ARGON2_PARALLELISM = 4;
const ARGON2_HASH_LEN    = 32;      // 256-bit → kunci AES-256

// ── State ─────────────────────────────────────────────────────────────
const state = {
    encrypt: { file: null, objectUrl: null },
    decrypt: { file: null, objectUrl: null }
};

// ── Helper: Uint8Array → hex string ──────────────────────────────────
function toHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Helper: bangun binary file .enc ──────────────────────────────────
function buildEncFile(salt, iv, filename, ciphertextWithTag) {
    const filenameBytes = new TextEncoder().encode(filename);
    const fnameLenBuf   = new ArrayBuffer(2);
    new DataView(fnameLenBuf).setUint16(0, filenameBytes.length, false); // big-endian

    const total = MAGIC.length + salt.length + iv.length + 2 + filenameBytes.length + ciphertextWithTag.length;
    const result = new Uint8Array(total);
    let offset = 0;

    result.set(MAGIC,                       offset); offset += MAGIC.length;
    result.set(salt,                         offset); offset += salt.length;
    result.set(iv,                           offset); offset += iv.length;
    result.set(new Uint8Array(fnameLenBuf),  offset); offset += 2;
    result.set(filenameBytes,                offset); offset += filenameBytes.length;
    result.set(ciphertextWithTag,            offset);

    return result;
}

// ── Helper: parse binary file .enc ───────────────────────────────────
function parseEncFile(encBytes) {
    // Validasi magic bytes
    for (let i = 0; i < MAGIC.length; i++) {
        if (encBytes[i] !== MAGIC[i]) {
            throw new Error('File tidak valid (bukan format SecureFile .enc).');
        }
    }

    let offset = MAGIC.length;

    const salt     = encBytes.slice(offset, offset + SALT_LEN);  offset += SALT_LEN;
    const iv       = encBytes.slice(offset, offset + IV_LEN);     offset += IV_LEN;
    const fnameLen = (encBytes[offset] << 8) | encBytes[offset + 1]; offset += 2;
    const fnameBytes = encBytes.slice(offset, offset + fnameLen); offset += fnameLen;
    const ciphertextWithTag = encBytes.slice(offset);

    const filename = new TextDecoder().decode(fnameBytes);
    return { salt, iv, filename, ciphertextWithTag };
}

// ── Tab Switching ──────────────────────────────────────────────────────
function switchTab(tab) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.getElementById(`tab-btn-${tab}`).classList.add('active');
    document.getElementById(`panel-${tab}`).classList.add('active');
}

// ── File Size Formatter ────────────────────────────────────────────────
function formatSize(bytes) {
    if (bytes < 1024)       return bytes + ' B';
    if (bytes < 1048576)    return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
    return (bytes / 1073741824).toFixed(2) + ' GB';
}

// ── File Icon ─────────────────────────────────────────────────────────
function getFileIcon(name) {
    const ext = (name.split('.').pop() || '').toLowerCase();
    const icons = {
        pdf:'📄', jpg:'🖼️', jpeg:'🖼️', png:'🖼️', gif:'🖼️', webp:'🖼️', svg:'🖼️', bmp:'🖼️',
        zip:'📦', rar:'📦', '7z':'📦', tar:'📦', gz:'📦',
        mp4:'🎬', mkv:'🎬', avi:'🎬', mov:'🎬', webm:'🎬',
        mp3:'🎵', wav:'🎵', ogg:'🎵', flac:'🎵',
        doc:'📝', docx:'📝', xls:'📊', xlsx:'📊', ppt:'📊', pptx:'📊',
        txt:'📃', csv:'📊', js:'💻', py:'💻', html:'💻', css:'💻', json:'💻', enc:'🔒'
    };
    return icons[ext] || '📁';
}

// ── Drop Zone Setup ────────────────────────────────────────────────────
function setupDropZone(zoneId, inputId, tab, acceptExt) {
    const zone  = document.getElementById(zoneId);
    const input = document.getElementById(inputId);

    zone.addEventListener('click', (e) => { if (e.target !== input) input.click(); });

    zone.addEventListener('dragover',  (e) => { e.preventDefault(); zone.classList.add('drag-over'); });
    zone.addEventListener('dragleave', ()  => zone.classList.remove('drag-over'));

    zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('drag-over');
        if (e.dataTransfer.files.length > 0) handleFileSelect(e.dataTransfer.files[0], tab, acceptExt);
    });

    input.addEventListener('change', () => {
        if (input.files.length > 0) handleFileSelect(input.files[0], tab, acceptExt);
    });
}

function handleFileSelect(file, tab, acceptExt) {
    if (acceptExt && !file.name.toLowerCase().endsWith(acceptExt)) {
        flashZone(`drop-${tab}`, `❌ Hanya file ${acceptExt} yang diterima.`);
        return;
    }
    if (file.size > 500 * 1024 * 1024) {
        flashZone(`drop-${tab}`, '❌ File melebihi 500 MB.');
        return;
    }
    state[tab].file = file;
    showFileInfo(file, tab);
    hideAlert(tab);
    hideError(tab);
}

function showFileInfo(file, tab) {
    const info = document.getElementById(`file-info-${tab}`);
    info.querySelector('.file-info-icon').textContent = getFileIcon(file.name);
    info.querySelector('.file-info-name').textContent = file.name;
    info.querySelector('.file-info-meta').textContent = `${formatSize(file.size)} · ${file.type || 'unknown type'}`;
    info.classList.add('show');
}

function removeFile(tab) {
    state[tab].file = null;
    if (state[tab].objectUrl) { URL.revokeObjectURL(state[tab].objectUrl); state[tab].objectUrl = null; }
    document.getElementById(`file-info-${tab}`).classList.remove('show');
    document.getElementById(`input-${tab}`).value = '';
    hideResult(tab);
    hideInspector(tab);
    hideAlert(tab);
    hideError(tab);
}

// ── Password Strength Meter ────────────────────────────────────────────
function checkStrength(password) {
    if (!password) return { score: 0, label: '', color: '', pct: '0%' };
    let score = 0;
    if (password.length >= 8)  score++;
    if (password.length >= 12) score++;
    if (password.length >= 16) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^a-zA-Z0-9]/.test(password)) score++;
    const levels = [
        { min:0, max:1, label:'Sangat Lemah',  color:'#ef4444', pct:'12%' },
        { min:2, max:2, label:'Lemah',          color:'#f97316', pct:'28%' },
        { min:3, max:3, label:'Sedang',         color:'#eab308', pct:'50%' },
        { min:4, max:5, label:'Kuat',           color:'#22c55e', pct:'75%' },
        { min:6, max:9, label:'Sangat Kuat 💪', color:'#10b981', pct:'100%' }
    ];
    return levels.find(l => score >= l.min && score <= l.max) || levels[0];
}

function onPasswordInput(tab) {
    const val   = document.getElementById(`key-${tab}`).value;
    const res   = checkStrength(val);
    const fill  = document.getElementById(`strength-fill-${tab}`);
    const label = document.getElementById(`strength-label-${tab}`);
    fill.style.width      = val ? res.pct : '0%';
    fill.style.background = res.color;
    label.textContent     = val ? res.label : '';
    label.style.color     = res.color;
}

function togglePassword(tab) {
    const input = document.getElementById(`key-${tab}`);
    const btn   = document.getElementById(`eye-${tab}`);
    input.type  = input.type === 'password' ? 'text' : 'password';
    btn.textContent = input.type === 'password' ? '👁️' : '🙈';
}

// ── Alert / Result Helpers ─────────────────────────────────────────────
function hideAlert(tab)    { const el = document.getElementById(`alert-${tab}`);    if (el) el.classList.remove('show'); }
function hideResult(tab)   { const el = document.getElementById(`result-${tab}`);   if (el) el.classList.remove('show'); }
function hideInspector(tab){ const el = document.getElementById(`inspector-${tab}`); if (el) el.classList.remove('show'); }

function hideError(tab) {
    const el = document.getElementById(`error-${tab}`);
    if (el) { el.style.display = 'none'; el.classList.remove('show'); }
}

function showErrorCard(tab, msg) {
    hideResult(tab);
    const errCard = document.getElementById(`error-${tab}`);
    const errMsg  = document.getElementById(`error-msg-${tab}`);
    errMsg.textContent = msg;
    errCard.style.display = 'block';
    errCard.classList.add('show');
}

// ── Progress Helpers ───────────────────────────────────────────────────
function showProgress(tab, msg) {
    const wrap = document.getElementById(`progress-${tab}`);
    // Gunakan ID khusus agar tidak mengganggu spinner
    const lbl  = document.getElementById(`progress-msg-${tab}`);
    // Hapus emoji dari pesan agar tidak ada karakter yang ikut beranimasi
    lbl.textContent = msg.replace(/[\u{1F300}-\u{1FAFF}]/gu, '').trim();
    wrap.classList.add('show');
}
function hideProgress(tab) {
    document.getElementById(`progress-${tab}`).classList.remove('show');
}

// ── Show Result (Client-Side Download via Object URL) ─────────────────
function showResultEnc(tab, url, filename, origSize, encSize) {
    // Revoke old URL to free memory
    if (state[tab].objectUrl) URL.revokeObjectURL(state[tab].objectUrl);
    state[tab].objectUrl = url;

    const card = document.getElementById(`result-${tab}`);
    card.classList.add('show');

    const link = document.getElementById(`dl-btn-${tab}`);
    link.href     = url;
    link.download = filename;
    link.querySelector('.dl-name').textContent = filename;

    const meta = document.getElementById(`result-meta-${tab}`);
    if (meta) meta.textContent = `${formatSize(origSize)} → ${formatSize(encSize)} (+ header)`;
}

function showResultDec(tab, url, filename, fileSize) {
    if (state[tab].objectUrl) URL.revokeObjectURL(state[tab].objectUrl);
    state[tab].objectUrl = url;

    const card = document.getElementById(`result-${tab}`);
    card.classList.add('show');

    const link = document.getElementById(`dl-btn-${tab}`);
    link.href     = url;
    link.download = filename;
    link.querySelector('.dl-name').textContent = filename;

    const badge = document.getElementById(`auth-badge-${tab}`);
    if (badge) badge.style.display = 'inline-flex';

    const meta = document.getElementById(`result-meta-${tab}`);
    if (meta) meta.textContent = `Ukuran file: ${formatSize(fileSize)}`;
}

// ── Inspector Renderer ─────────────────────────────────────────────────
function renderInspector(tab, data, mode) {
    const card = document.getElementById(`inspector-${tab}`);
    const body = document.getElementById(`inspector-body-${tab}`);
    card.classList.add('show');
    const p = data.argon2_params || {};
    body.innerHTML = `
      <div class="step-card step-salt">
        <div class="step-header">
          <span class="step-num">Step 1</span>
          <span class="step-name">🎲 Salt Argon2id (${SALT_LEN} byte acak)</span>
        </div>
        <div class="step-body"><div class="step-value">${data.salt_hex || '—'}</div></div>
      </div>
      <div class="step-card step-argon">
        <div class="step-header">
          <span class="step-num">Step 2</span>
          <span class="step-name">⚙️ Parameter Argon2id (KDF)</span>
        </div>
        <div class="step-body">
          <table class="params-table">
            <tr><td>Tipe</td><td>${p.type || 'Argon2id'}</td></tr>
            <tr><td>Iterasi (time_cost)</td><td>${p.time_cost || 3}x</td></tr>
            <tr><td>Memori (memory_cost)</td><td>${p.memory_cost || '64 MB'}</td></tr>
            <tr><td>Paralelisme</td><td>${p.parallelism || 4} thread</td></tr>
            <tr><td>Panjang output</td><td>${p.hash_len || '32 byte (256-bit)'}</td></tr>
          </table>
        </div>
      </div>
      <div class="step-card step-key">
        <div class="step-header">
          <span class="step-num">Step 3</span>
          <span class="step-name">🔑 Derived Key AES-256 (dari Argon2id)</span>
        </div>
        <div class="step-body">
          <div class="step-value">${data.derived_key_hex || '—'} <em style="font-size:0.65rem">(sebagian di-mask)</em></div>
        </div>
      </div>
      <div class="step-card step-iv">
        <div class="step-header">
          <span class="step-num">Step 4</span>
          <span class="step-name">🎲 IV / Nonce AES-GCM (${IV_LEN} byte acak)</span>
        </div>
        <div class="step-body"><div class="step-value">${data.iv_hex || '—'}</div></div>
      </div>
      <div class="step-card step-tag">
        <div class="step-header">
          <span class="step-num">Step 5</span>
          <span class="step-name">🏷️ Auth Tag AES-GCM (16 byte)</span>
        </div>
        <div class="step-body">
          <div class="step-value">${data.auth_tag_hex || '—'}</div>
          ${mode === 'decrypt' && data.auth_tag_verified
            ? '<div class="verified-badge">✅ Auth Tag Terverifikasi — Password benar, file tidak dimodifikasi</div>'
            : ''}
        </div>
      </div>
      <div class="step-card step-cipher">
        <div class="step-header">
          <span class="step-num">Step 6</span>
          <span class="step-name">📦 Preview Ciphertext (20 byte pertama)</span>
        </div>
        <div class="step-body">
          <div class="step-value">${data.cipher_preview || '—'} <em style="font-size:0.65rem">...dan seterusnya</em></div>
        </div>
      </div>
    `;
}

function toggleInspector(tab) {
    const body  = document.getElementById(`inspector-body-${tab}`);
    const arrow = document.getElementById(`inspector-arrow-${tab}`);
    const hdr   = document.getElementById(`inspector-hdr-${tab}`);
    const open  = body.classList.toggle('show');
    arrow.classList.toggle('open', open);
    hdr.classList.toggle('open', open);
}

// ── Flash Helpers ──────────────────────────────────────────────────────
function flashZone(id, msg) {
    const zone = document.getElementById(id);
    zone.classList.add('highlight');
    const sub = zone.querySelector('.drop-subtitle');
    const original = sub.textContent;
    sub.textContent = msg;
    setTimeout(() => { zone.classList.remove('highlight'); sub.textContent = original; }, 2000);
}

function flashInput(id) {
    const input = document.getElementById(id);
    input.style.borderColor = '#ef4444';
    input.style.boxShadow   = '0 0 0 3px rgba(239,68,68,0.2)';
    input.focus();
    setTimeout(() => { input.style.borderColor = ''; input.style.boxShadow = ''; }, 2000);
}


// ══════════════════════════════════════════════════════════════════════
//  ENKRIPSI — 100% di Browser
// ══════════════════════════════════════════════════════════════════════
async function handleEncrypt() {
    const file     = state.encrypt.file;
    const password = document.getElementById('key-encrypt').value.trim();

    if (!file)     { flashZone('drop-encrypt', '⚠️ Pilih file terlebih dahulu!'); return; }
    if (!password) { flashInput('key-encrypt'); return; }

    const btn = document.getElementById('btn-encrypt');
    btn.disabled = true;
    hideResult('encrypt');
    hideError('encrypt');
    hideInspector('encrypt');
    showProgress('encrypt', '📂 Membaca file...');

    try {
        // 1. Baca file sebagai bytes
        const fileBytes = new Uint8Array(await file.arrayBuffer());

        // 2. Generate salt & IV secara kriptografi aman
        const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
        const iv   = crypto.getRandomValues(new Uint8Array(IV_LEN));

        // 3. Argon2id KDF — jalankan di WASM (1–3 detik)
        showProgress('encrypt', '⚙️ Argon2id: menghitung kunci (64 MB RAM)...');
        await new Promise(r => setTimeout(r, 60)); // beri waktu UI update

        const argon2Result = await argon2.hash({
            pass:        password,
            salt:        salt,
            time:        ARGON2_TIME_COST,
            mem:         ARGON2_MEMORY_COST,
            parallelism: ARGON2_PARALLELISM,
            hashLen:     ARGON2_HASH_LEN,
            type:        argon2.ArgonType.Argon2id
        });
        const derivedKey = argon2Result.hash; // Uint8Array 32 byte

        // 4. Import key untuk AES-GCM
        showProgress('encrypt', '🔒 AES-256-GCM: mengenkripsi...');
        const cryptoKey = await crypto.subtle.importKey(
            'raw', derivedKey, { name: 'AES-GCM' }, false, ['encrypt']
        );

        // 5. Enkripsi — Web Crypto API otomatis append Auth Tag 16 byte di akhir
        const ciphertextWithTag = new Uint8Array(
            await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, fileBytes)
        );

        const authTag   = ciphertextWithTag.slice(-AUTH_TAG_LEN);
        const ciphertext = ciphertextWithTag.slice(0, -AUTH_TAG_LEN);

        // 6. Bangun file .enc dengan format biner yang sama
        const encBytes = buildEncFile(salt, iv, file.name, ciphertextWithTag);

        // 7. Buat Object URL untuk download langsung dari browser
        const blob = new Blob([encBytes], { type: 'application/octet-stream' });
        const url  = URL.createObjectURL(blob);

        // 8. Inspector data
        const derivedHex = toHex(derivedKey);
        const inspector = {
            salt_hex:        toHex(salt),
            iv_hex:          toHex(iv),
            derived_key_hex: derivedHex.slice(0, 8) + '...' + derivedHex.slice(-8),
            auth_tag_hex:    toHex(authTag),
            cipher_preview:  toHex(ciphertext.slice(0, 20)),
            argon2_params: {
                type:        'Argon2id',
                time_cost:   ARGON2_TIME_COST,
                memory_cost: `${ARGON2_MEMORY_COST / 1024} MB`,
                parallelism: ARGON2_PARALLELISM,
                hash_len:    `${ARGON2_HASH_LEN} byte (256-bit)`
            }
        };

        showResultEnc('encrypt', url, file.name + '.enc', file.size, encBytes.length);
        renderInspector('encrypt', inspector, 'encrypt');
        toggleInspector('encrypt');

    } catch (err) {
        showErrorCard('encrypt', '❌ Enkripsi gagal: ' + err.message);
    } finally {
        btn.disabled = false;
        hideProgress('encrypt');
    }
}


// ══════════════════════════════════════════════════════════════════════
//  DEKRIPSI — 100% di Browser
// ══════════════════════════════════════════════════════════════════════
async function handleDecrypt() {
    const file     = state.decrypt.file;
    const password = document.getElementById('key-decrypt').value.trim();

    if (!file)     { flashZone('drop-decrypt', '⚠️ Pilih file .enc terlebih dahulu!'); return; }
    if (!password) { flashInput('key-decrypt'); return; }

    const btn = document.getElementById('btn-decrypt');
    btn.disabled = true;
    hideResult('decrypt');
    hideError('decrypt');
    hideInspector('decrypt');
    showProgress('decrypt', '📂 Membaca file .enc...');

    try {
        // 1. Baca file .enc sebagai bytes
        const encBytes = new Uint8Array(await file.arrayBuffer());

        // 2. Parse header (validasi magic + ambil salt, iv, filename)
        const { salt, iv, filename, ciphertextWithTag } = parseEncFile(encBytes);

        // 3. Argon2id KDF
        showProgress('decrypt', '⚙️ Argon2id: merekonstruksi kunci (64 MB RAM)...');
        await new Promise(r => setTimeout(r, 60));

        const argon2Result = await argon2.hash({
            pass:        password,
            salt:        salt,
            time:        ARGON2_TIME_COST,
            mem:         ARGON2_MEMORY_COST,
            parallelism: ARGON2_PARALLELISM,
            hashLen:     ARGON2_HASH_LEN,
            type:        argon2.ArgonType.Argon2id
        });
        const derivedKey = argon2Result.hash;

        // 4. Import key untuk AES-GCM
        showProgress('decrypt', '🔓 AES-256-GCM: mendekripsi...');
        const cryptoKey = await crypto.subtle.importKey(
            'raw', derivedKey, { name: 'AES-GCM' }, false, ['decrypt']
        );

        // 5. Dekripsi — Web Crypto API otomatis verifikasi Auth Tag
        //    Jika password salah atau file dimodifikasi → throw Exception
        let fileBytes;
        try {
            fileBytes = new Uint8Array(
                await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, ciphertextWithTag)
            );
        } catch {
            throw new Error('Password salah atau file telah dimodifikasi/rusak. Auth Tag tidak cocok.');
        }

        const authTag    = ciphertextWithTag.slice(-AUTH_TAG_LEN);
        const ciphertext = ciphertextWithTag.slice(0, -AUTH_TAG_LEN);

        // 6. Buat Object URL untuk download
        const blob = new Blob([fileBytes]);
        const url  = URL.createObjectURL(blob);

        // 7. Inspector data
        const derivedHex = toHex(derivedKey);
        const inspector = {
            salt_hex:           toHex(salt),
            iv_hex:             toHex(iv),
            derived_key_hex:    derivedHex.slice(0, 8) + '...' + derivedHex.slice(-8),
            auth_tag_hex:       toHex(authTag),
            auth_tag_verified:  true,
            cipher_preview:     toHex(ciphertext.slice(0, 20)),
            argon2_params: {
                type:        'Argon2id',
                time_cost:   ARGON2_TIME_COST,
                memory_cost: `${ARGON2_MEMORY_COST / 1024} MB`,
                parallelism: ARGON2_PARALLELISM,
                hash_len:    `${ARGON2_HASH_LEN} byte (256-bit)`
            }
        };

        showResultDec('decrypt', url, filename, fileBytes.length);
        renderInspector('decrypt', inspector, 'decrypt');
        toggleInspector('decrypt');

    } catch (err) {
        showErrorCard('decrypt', '❌ ' + err.message);
    } finally {
        btn.disabled = false;
        hideProgress('decrypt');
    }
}


// ── Init ───────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    setupDropZone('drop-encrypt', 'input-encrypt', 'encrypt', null);
    setupDropZone('drop-decrypt', 'input-decrypt', 'decrypt', '.enc');
    switchTab('encrypt');
});
