// OmniGupt Pro - BUNDLED VERSION (No ES Imports - Works on file://)
// Includes crypto + backend functions inline + file:// fallbacks

// === CRYPTOGRAPHIC HELPERS & UTILITIES ===
function strToBytes(str) {
    return new TextEncoder().encode(str);
}

function bytesToStr(bytes) {
    return new TextDecoder().decode(bytes);
}

function bytesToBase64(bytes) {
    let binary = '';
    const len = bytes.byteLength;
    const view = new Uint8Array(bytes);
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(view[i]);
    }
    return window.btoa(binary);
}

function base64ToBytes(base64) {
    const binary = window.atob(base64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function hexToBytes(hex) {
    const cleanHex = hex.replace(/\s/g, '');
    const len = cleanHex.length;
    const bytes = new Uint8Array(len / 2);
    for (let i = 0; i < len; i += 2) {
        bytes[i / 2] = parseInt(cleanHex.substring(i, i + 2), 16);
    }
    return bytes;
}

function isGcmPayload(text) {
    try {
        const decoded = window.atob(text.trim());
        if (decoded.startsWith('{"version":') && decoded.includes('"algorithm":"AES-256-GCM"')) {
            return true;
        }
    } catch (e) { }
    return false;
}

/**
 * CRITICAL CRYPTOGRAPHIC DESIGN NOTES:
 * 
 * 1. Why IV uniqueness matters:
 *    Under AES-GCM, repeating an IV (Initialization Vector) with the same key breaks the security
 *    of the cipher completely. It allows an attacker to reconstruct the hash key used for
 *    authentication and decrypt other messages encrypted under the same key. The IV must be
 *    unique for every single encryption. We generate a fresh 96-bit random IV for every operation.
 * 
 * 2. Why AES-GCM provides integrity:
 *    Unlike AES-CBC which only provides confidentiality, AES-GCM is an Authenticated Encryption
 *    with Associated Data (AEAD) mode. It computes an authentication tag over the ciphertext
 *    and optional associated data. This ensures that any modification of the ciphertext, IV,
 *    or metadata during transit is detected during decryption, preventing active tampering attacks.
 * 
 * 3. Why the IV is not secret:
 *    The IV's purpose is to ensure that encrypting the same plaintext twice produces different
 *    ciphertexts. It does not need to be hidden from an attacker. It is public and is safely
 *    transported alongside the ciphertext.
 * 
 * 4. Why the salt is not secret:
 *    The salt is used in PBKDF2 to prevent pre-computed dictionary (rainbow table) attacks by
 *    ensuring that identical passphrases yield unique encryption keys. The salt is public metadata
 *    required for decryption KDF derivation and does not need to be hidden.
 * 
 * 5. Why keys and passphrases must never be stored:
 *    Persisting raw secret keys or passphrases on disk (e.g. database or localStorage) leaves them
 *    vulnerable to local extraction, malware, or server compromise. A secure cryptography tool
 *    should process keys purely in memory and discard them immediately after use.
 */

async function encryptGCM(plaintext, key, isRaw) {
    if (!plaintext) {
        throw new Error('Plaintext cannot be empty.');
    }
    const cleanKey = key.replace(/\s/g, '');
    let cryptoKey;
    let saltBytes = null;

    if (isRaw) {
        if (!/^[0-9a-f]{64}$/i.test(cleanKey)) {
            throw new Error('For AES-GCM raw mode, the key must be a valid 64-character Hex string (256-bit).');
        }
        const rawKeyBytes = hexToBytes(cleanKey);
        cryptoKey = await window.crypto.subtle.importKey(
            'raw',
            rawKeyBytes,
            { name: 'AES-GCM' },
            false,
            ['encrypt']
        );
    } else {
        const passphraseBytes = strToBytes(key);
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            passphraseBytes,
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );

        saltBytes = new Uint8Array(16);
        window.crypto.getRandomValues(saltBytes);

        cryptoKey = await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: saltBytes,
                iterations: 600000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        );
    }

    const ivBytes = new Uint8Array(12);
    window.crypto.getRandomValues(ivBytes);

    const plaintextBytes = strToBytes(plaintext);

    const ciphertextBuffer = await window.crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: ivBytes,
            tagLength: 128
        },
        cryptoKey,
        plaintextBytes
    );

    const ciphertextBytes = new Uint8Array(ciphertextBuffer);

    const payload = {
        version: 1,
        algorithm: 'AES-256-GCM',
        iv: bytesToBase64(ivBytes),
        ciphertext: bytesToBase64(ciphertextBytes)
    };

    if (!isRaw && saltBytes) {
        payload.kdf = 'PBKDF2';
        payload.hash = 'SHA-256';
        payload.iterations = 600000;
        payload.salt = bytesToBase64(saltBytes);
    }

    const jsonStr = JSON.stringify(payload);
    return bytesToBase64(strToBytes(jsonStr));
}

async function decryptGCM(base64Payload, key, isRaw) {
    try {
        const jsonBytes = base64ToBytes(base64Payload);
        const jsonStr = bytesToStr(jsonBytes);
        const payload = JSON.parse(jsonStr);

        if (payload.version !== 1) {
            throw new Error('Unsupported payload version.');
        }
        if (payload.algorithm !== 'AES-256-GCM') {
            throw new Error('Incorrect algorithm inside payload.');
        }
        if (!payload.iv || !payload.ciphertext) {
            throw new Error('Missing required GCM payload parameters.');
        }

        const ivBytes = base64ToBytes(payload.iv);
        if (ivBytes.length !== 12) {
            throw new Error('Invalid GCM IV length.');
        }

        const ciphertextBytes = base64ToBytes(payload.ciphertext);
        const cleanKey = key.replace(/\s/g, '');
        let cryptoKey;

        if (isRaw) {
            if (!/^[0-9a-f]{64}$/i.test(cleanKey)) {
                throw new Error('For AES-GCM raw mode, the key must be a valid 64-character Hex string (256-bit).');
            }
            const rawKeyBytes = hexToBytes(cleanKey);
            cryptoKey = await window.crypto.subtle.importKey(
                'raw',
                rawKeyBytes,
                { name: 'AES-GCM' },
                false,
                ['decrypt']
            );
        } else {
            if (payload.kdf !== 'PBKDF2' || !payload.salt) {
                throw new Error('Missing KDF parameters.');
            }

            const iterations = payload.iterations !== undefined ? Number(payload.iterations) : 600000;
            if (isNaN(iterations) || iterations < 1000 || iterations > 2000000) {
                throw new Error('Invalid or unsafe PBKDF2 iteration parameter count.');
            }

            const saltBytes = base64ToBytes(payload.salt);
            const passphraseBytes = strToBytes(key);

            const keyMaterial = await window.crypto.subtle.importKey(
                'raw',
                passphraseBytes,
                { name: 'PBKDF2' },
                false,
                ['deriveKey']
            );

            cryptoKey = await window.crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: saltBytes,
                    iterations: iterations,
                    hash: payload.hash || 'SHA-256'
                },
                keyMaterial,
                { name: 'AES-GCM', length: 256 },
                false,
                ['decrypt']
            );
        }

        const plaintextBuffer = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: ivBytes,
                tagLength: 128
            },
            cryptoKey,
            ciphertextBytes
        );

        return bytesToStr(new Uint8Array(plaintextBuffer));
    } catch (e) {
        throw new Error(e.message && (e.message.includes('iteration') || e.message.includes('parameters') || e.message.includes('version')) ? e.message : 'Authentication failed. The encrypted data may have been modified or the key is incorrect.');
    }
}

// === CRYPTO FUNCTIONS (from js/crypto.js) ===
async function cryptoEncrypt(algo, text, key, isRaw, ivText) {
    if (algo === 'AES-GCM') {
        return await encryptGCM(text, key, isRaw);
    }

    if (isRaw) {
        if (algo !== 'AES') {
            throw new Error('Raw key mode is only supported for AES.');
        }
        const cleanKey = key.replace(/\s/g, '');
        const cleanIV = (ivText || '').replace(/\s/g, '');

        if (!/^[0-9a-f]{32,64}$/i.test(cleanKey)) {
            throw new Error('For Raw AES, the secret key must be a valid 32 or 64 character Hex string.');
        }

        const keyBytes = CryptoJS.enc.Hex.parse(cleanKey);

        let ivBytes;
        if (cleanIV) {
            if (!/^[0-9a-f]{32}$/i.test(cleanIV)) {
                throw new Error('For Raw AES, the IV must be a valid 32 character Hex string.');
            }
            ivBytes = CryptoJS.enc.Hex.parse(cleanIV);
        } else {
            // Generate a secure random 16-byte IV instead of zero IV
            const randomArray = new Uint8Array(16);
            window.crypto.getRandomValues(randomArray);
            const randomIvHex = Array.from(randomArray, b => b.toString(16).padStart(2, '0')).join('');
            ivBytes = CryptoJS.enc.Hex.parse(randomIvHex);
        }

        const encrypted = CryptoJS.AES.encrypt(text, keyBytes, {
            iv: ivBytes,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });

        const ciphertextHex = encrypted.ciphertext.toString(CryptoJS.enc.Hex);
        const ivHex = ivBytes.toString(CryptoJS.enc.Hex);
        return ivHex + ':' + ciphertextHex;
    } else {
        return CryptoJS[algo].encrypt(text, key).toString();
    }
}

async function cryptoDecrypt(algo, text, key, isRaw, ivText) {
    try {
        if (algo === 'AES-GCM' || isGcmPayload(text)) {
            return await decryptGCM(text, key, isRaw);
        }

        if (isRaw) {
            if (algo !== 'AES') {
                throw new Error('Raw key mode is only supported for AES.');
            }
            const cleanKey = key.replace(/\s/g, '');
            if (!/^[0-9a-f]{32,64}$/i.test(cleanKey)) {
                throw new Error('For Raw AES, the secret key must be a valid 32 or 64 character Hex string.');
            }
            const keyBytes = CryptoJS.enc.Hex.parse(cleanKey);

            let cleanIV = (ivText || '').replace(/\s/g, '');
            let cipherTextStr = text.trim();

            if (cipherTextStr.includes(':')) {
                const parts = cipherTextStr.split(':');
                if (parts.length === 2 && parts[0].length === 32) {
                    cleanIV = parts[0];
                    cipherTextStr = parts[1];
                }
            }

            if (!cleanIV) {
                cleanIV = '00000000000000000000000000000000';
            }

            if (!/^[0-9a-f]{32}$/i.test(cleanIV)) {
                throw new Error('For Raw AES, the IV must be a valid 32 character Hex string.');
            }

            const ivBytes = CryptoJS.enc.Hex.parse(cleanIV);

            let ciphertextParams;
            if (/^[0-9a-f]+$/i.test(cipherTextStr)) {
                ciphertextParams = CryptoJS.lib.CipherParams.create({
                    ciphertext: CryptoJS.enc.Hex.parse(cipherTextStr)
                });
            } else {
                ciphertextParams = CryptoJS.lib.CipherParams.create({
                    ciphertext: CryptoJS.enc.Base64.parse(cipherTextStr)
                });
            }

            const decrypted = CryptoJS.AES.decrypt(ciphertextParams, keyBytes, {
                iv: ivBytes,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
            });

            const result = decrypted.toString(CryptoJS.enc.Utf8);
            if (!result) {
                throw new Error('Decryption failed');
            }
            return result;
        } else {
            const bytes = CryptoJS[algo].decrypt(text, key);
            const result = bytes.toString(CryptoJS.enc.Utf8);
            if (!result) {
                throw new Error('Decryption failed');
            }
            return result;
        }
    } catch (e) {
        throw new Error(e.message && (e.message.includes('iteration') || e.message.includes('parameters') || e.message.includes('version')) ? e.message : 'Decryption failed. The key may be incorrect or the encrypted data may be invalid.');
    }
}

function checkKeyStrength(key, isRawMode) {
    const cleanKey = key.replace(/\s/g, '');
    const length = cleanKey.length;

    if (isRawMode) {
        const isHex = /^[0-9a-f]{32,64}$/i.test(cleanKey);
        if (isHex) {
            if (length === 64) {
                return { score: 100, label: 'VERY STRONG', hint: '256-BIT HEX' };
            } else if (length === 32) {
                return { score: 85, label: 'STRONG', hint: '128-BIT HEX' };
            } else {
                return { score: 50, label: 'MODERATE', hint: 'HEX KEY' };
            }
        }
    }

    const hasUpper = /[A-Z]/.test(key);
    const hasLower = /[a-z]/.test(key);
    const hasNum = /\d/.test(key);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(key);

    let charsetSize = 0;
    if (hasLower) charsetSize += 26;
    if (hasUpper) charsetSize += 26;
    if (hasNum) charsetSize += 10;
    if (hasSpecial) charsetSize += 32;
    if (charsetSize === 0) charsetSize = 1;

    // Apply penalty for repeated characters
    const uniqueChars = new Set(key.split('')).size;
    const uniquenessPenalty = length > 0 ? Math.pow(uniqueChars / length, 0.7) : 1;
    const effectiveLength = length * uniquenessPenalty;

    // Entropy = effectiveLength * log2(charset)
    // 100 bits of entropy = 100% score
    let entropy = effectiveLength * Math.log2(charsetSize);

    // To ensure the user can reach 100 without needing 20+ chars, we'll scale it slightly.
    // E.g. length 12 with all 4 types = 12 * log2(94) = 12 * 6.55 = 78.
    // Let's multiply by 1.25 so a good 12-char password hits near 100.
    let score = entropy * 1.25;

    let finalScore = Math.floor(Math.min(score, 100));
    if (length > 0 && finalScore < 1) finalScore = 1;

    let label = 'VERY WEAK';
    let hint = 'TOO SHORT';

    if (finalScore >= 85) {
        label = 'VERY STRONG';
        hint = 'HIGH ENTROPY';
    } else if (finalScore >= 70) {
        label = 'STRONG';
        hint = 'GOOD PASSPHRASE';
    } else if (finalScore >= 50) {
        label = 'MODERATE';
        hint = 'INCREASE LENGTH';
    } else if (finalScore >= 25) {
        label = 'WEAK';
        hint = 'ADD SYMBOLS + NUMBERS';
    }

    return {
        score: finalScore,
        label: label,
        hint: hint
    };
}

// // === BACKEND OPERATION LOGGER ===
async function saveOperation(op) {
    if (!backendAvailable) {
        console.log('Backend offline - operation logged locally only');
        return;
    }
    try {
        await fetch('http://localhost:5000/cipher', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                sessionId: sessionStorage.getItem('omniSessionId') || 'anonymous',
                algo: op.algorithm,
                mode: op.mode,
                type: op.type,
                inputSize: op.inputSize,
                outputSize: op.outputSize,
                status: op.status
            })
        });
    } catch (e) {
        console.warn('Backend connection failed during operation logging:', e);
    }
}
function getHistoryFake() {
    return [];
}

// Detect backend
let backendAvailable = false;
async function testBackend() {
    try {
        const res = await fetch('http://localhost:5000/');
        backendAvailable = res.ok;
    } catch {
        backendAvailable = false;
    }
}

// === MAIN APP (original index.js with crypto inline) ===
let currentMethod = 'AES-GCM';
let isRawMode = false;
let lastOperation = null;

const algorithmMetadata = {
    'AES-GCM': {
        displayName: 'AES-256-GCM',
        category: 'MODERN / RECOMMENDED',
        badge: 'RECOMMENDED',
        level: 'recommended',
        description: 'Authenticated encryption providing confidentiality and integrity protection.',
        educational: 'AES-256-GCM is the modern industry standard for symmetric encryption. It provides both confidentiality (hiding data) and integrity/authenticity verification (confirming data has not been modified) in a single high-performance operation.'
    },
    'AES': {
        displayName: 'AES (Legacy CBC)',
        category: 'LEGACY COMPATIBILITY',
        badge: 'LEGACY COMPATIBILITY',
        level: 'legacy',
        description: 'CBC provides confidentiality but does not provide built-in authentication. Prefer AES-256-GCM for new encryption operations.',
        educational: 'AES in Cipher Block Chaining (CBC) mode is a legacy standard. While it remains secure against passive eavesdropping when implemented with unique, random IVs, it does not offer built-in ciphertext integrity verification (non-malleability), making it vulnerable to active tampering or bit-flipping attacks if not combined with a separate MAC.'
    },
    'DES': {
        displayName: 'DES',
        category: 'LEGACY / EDUCATIONAL',
        badge: 'LEGACY',
        level: 'danger',
        description: 'DES is a legacy encryption algorithm with an effective 56-bit key and is not recommended for protecting modern sensitive data. It is included in OmniGupt for educational and compatibility purposes.',
        educational: 'DES (Data Encryption Standard) uses an extremely small key length of 56 bits. With modern computing power, DES can be brute-forced in a matter of hours. It is obsolete and should only be studied or used for legacy file compatibility.'
    },
    'TripleDES': {
        displayName: 'Triple DES (3DES)',
        category: 'LEGACY / EDUCATIONAL',
        badge: 'DEPRECATED',
        level: 'deprecated',
        description: 'Triple DES is a deprecated legacy algorithm. It is included for educational study and legacy compatibility.',
        educational: 'Triple DES (3DES) applies the DES algorithm three times. While it increases the key length, it suffers from a small block size (64 bits) which makes it vulnerable to Sweet32 collision attacks when encrypting large amounts of data. It is also slow and has been retired by NIST.'
    },
    'Rabbit': {
        displayName: 'Rabbit',
        category: 'LEGACY / EDUCATIONAL',
        badge: 'LEGACY / EDUCATIONAL',
        level: 'legacy',
        description: 'Rabbit is included for cryptography education and compatibility. For new applications, prefer a modern authenticated encryption algorithm such as AES-256-GCM.',
        educational: 'Rabbit is a stream cipher first designed in 2003. Although it remains fast in software, it has not undergone the global scrutiny or standardization of modern stream ciphers like ChaCha20, nor does it provide authenticated encryption.'
    }
};

document.addEventListener('DOMContentLoaded', () => {
    // Securely initialize session ID if missing
    if (!sessionStorage.getItem('omniSessionId')) {
        const array = new Uint32Array(4);
        window.crypto.getRandomValues(array);
        sessionStorage.setItem('omniSessionId', Array.from(array, x => x.toString(16)).join(''));
    }

    setActiveButton('AES-GCM');
    document.getElementById('secret-key').addEventListener('input', updateStrength);
    const ivEl = document.getElementById('iv-input');
    if (ivEl) {
        ivEl.addEventListener('input', updateStrength);
    }
    document.querySelectorAll('.method-btn-card').forEach(btn => btn.addEventListener('click', () => setActiveButton(btn.dataset.method)));
    updateStrength();
    testBackend(); // Check if server running

    migrateLegacyAuditStorage();
    renderAuditHistoryUI();
});

function setActiveButton(method) {
    currentMethod = method;
    document.querySelectorAll('.method-btn-card').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.method === method);
        btn.setAttribute('aria-selected', btn.dataset.method === method ? 'true' : 'false');
    });
    document.getElementById('statusText').textContent = `${method} Active`;

    // Update warning box
    const meta = algorithmMetadata[method];
    if (meta) {
        const box = document.getElementById('algo-warning-box');
        const badge = document.getElementById('algo-badge');
        const text = document.getElementById('algo-warning-text');
        const edu = document.getElementById('algo-edu-text');

        if (box && badge && text && edu) {
            box.className = 'alert-box';
            box.classList.add('level-' + meta.level);

            badge.textContent = `${meta.category} - ${meta.badge}`;
            text.textContent = meta.description;
            edu.textContent = meta.educational;
        }
    }

    // Force passphrase KDF mode on legacy ciphers
    if (method !== 'AES-GCM' && method !== 'AES') {
        const rawToggleBtn = document.getElementById('mode-raw');
        if (rawToggleBtn) {
            rawToggleBtn.disabled = true;
            rawToggleBtn.style.opacity = '0.4';
            rawToggleBtn.style.cursor = 'not-allowed';
            rawToggleBtn.title = 'Raw key mode is not supported by legacy ciphers';
        }
        setKeyMode('passphrase');
    } else {
        const rawToggleBtn = document.getElementById('mode-raw');
        if (rawToggleBtn) {
            rawToggleBtn.disabled = false;
            rawToggleBtn.style.opacity = '1';
            rawToggleBtn.style.cursor = 'pointer';
            rawToggleBtn.title = '';
        }
    }

    updateStrength();
    updateAdvancedSettingsUI();
}

window.updateStrengthVisual = function (strengthPercentage) {
    const strengthFill = document.getElementById('barFill');
    const strengthLabel = document.getElementById('strengthText');

    if (!strengthFill) return;

    const percentage = Math.max(
        0,
        Math.min(100, Number(strengthPercentage) || 0)
    );

    if (percentage === 0) {
        strengthFill.style.width = '0%';
        strengthFill.style.background = 'transparent';
        strengthFill.style.boxShadow = 'none';
        if (strengthLabel) strengthLabel.style.color = 'var(--text-muted)';
        return;
    }

    const hue = percentage * 1.2;
    const color = `hsl(${hue}, 75%, 68%)`;

    strengthFill.style.width = `${percentage}%`;
    strengthFill.style.background = 'none';
    strengthFill.style.backgroundColor = color;
    strengthFill.style.boxShadow = `0 0 8px hsla(${hue}, 75%, 68%, 0.28)`;

    if (strengthLabel) {
        strengthLabel.style.color = color;
    }
}

function updateStrength() {
    const key = document.getElementById('secret-key').value;
    const modeIndicator = document.getElementById('mode-indicator');

    const strength = checkKeyStrength(key, isRawMode);
    const text = document.getElementById('strengthText');
    const hint = document.getElementById('strengthHint');

    if (key.length === 0) {
        window.updateStrengthVisual(0);
        if (text) {
            text.textContent = 'AWAITING PASSPHRASE';
        }
        if (hint) hint.textContent = '';
    } else {
        const percentage = Math.max(0, Math.min(100, Number(strength.score) || 0));
        window.updateStrengthVisual(percentage);

        if (text) {
            text.textContent = strength.label + ' · ' + percentage + '%';
        }
        if (hint) hint.textContent = strength.hint || '';
    }

    if (modeIndicator) {
        modeIndicator.textContent = isRawMode ? '🔧 RAW KEY' : '💬 PASSPHRASE';
        modeIndicator.style.color = isRawMode ? '#ffaa00' : '#00ff88';
    }
}

// ==========================================
// TEMPORARY DEBUG VISUALIZATION
// ==========================================
window.testMeterContinuously = function () {
    let p = 1;
    const interval = setInterval(() => {
        if (p > 100) {
            clearInterval(interval);
            updateStrength(); // reset to whatever is in the box
            return;
        }
        // Force the visual update for this exact integer
        window.updateStrengthVisual(p);

        const text = document.getElementById('strengthText');
        if (text) {
            text.textContent = `TESTING · ${p}%`;
        }
        p++;
    }, 40); // 40ms per step, ~4 seconds total
};

document.addEventListener('DOMContentLoaded', () => {
    // Auto-run test on load so user can visually verify
    setTimeout(window.testMeterContinuously, 500);
});

function toggleKeyView() {
    const input = document.getElementById('secret-key');
    input.type = input.type === 'password' ? 'text' : 'password';
}

function genKey() {
    if (isRawMode) {
        // Generate secure 256-bit hex key (32 bytes = 64 hex chars)
        const array = new Uint8Array(32);
        window.crypto.getRandomValues(array);
        const keyHex = Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
        document.getElementById('secret-key').value = keyHex;
        showNotification('Secure 256-bit Hex Key generated!', 'success');
    } else {
        // Generate secure passphrase (24 characters)
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
        const array = new Uint32Array(24);
        window.crypto.getRandomValues(array);
        let key = 'OmniGupt-';
        for (let i = 0; i < 24; i++) {
            key += chars[array[i] % chars.length];
        }
        document.getElementById('secret-key').value = key;
        showNotification('Secure passphrase generated!', 'success');
    }
    updateStrength();
}

async function encryptText() {
    const text = document.getElementById('encrypt-input').value.trim();
    const key = document.getElementById('secret-key').value.trim();
    const iv = document.getElementById('iv-input')?.value.trim() || null;

    if (!text) {
        showNotification('Validation Error: Please enter plain text to encrypt.', 'warning');
        document.getElementById('statusText').textContent = 'Enter text first';
        return;
    }
    if (!key) {
        showNotification('Validation Error: Secret key or passphrase is required.', 'error');
        document.getElementById('statusText').textContent = 'Key required';
        return;
    }

    try {
        const encrypted = await cryptoEncrypt(currentMethod, text, key, isRawMode, iv);
        document.getElementById('result-area').value = encrypted;
        document.getElementById('statusText').textContent = `Ready`;

        const maskedKey = key.length > 4 ? key.substring(0, key.length - 4) + '****' : '****';
        lastOperation = {
            type: 'encrypt',
            algorithm: currentMethod,
            mode: isRawMode ? 'raw' : 'passphrase',
            inputSize: text.length,
            outputSize: encrypted.length,
            status: 'success',
            input: text,
            output: encrypted,
            key: maskedKey
        };

        showNotification('Text encrypted successfully!', 'success');
        await saveOperation(lastOperation);
    } catch (e) {
        document.getElementById('result-area').value = 'Encryption error: ' + e.message;
        document.getElementById('statusText').textContent = 'Ready';
        showNotification('Encryption failed: ' + e.message, 'error');
    }
}

async function decryptText() {
    const encrypted = document.getElementById('decrypt-input').value.trim();
    const key = document.getElementById('secret-key').value.trim();
    const iv = document.getElementById('iv-input')?.value.trim() || null;

    if (!encrypted) {
        showNotification('Validation Error: Please enter encrypted text to decrypt.', 'warning');
        document.getElementById('statusText').textContent = 'Ready';
        return;
    }
    if (!key) {
        showNotification('Validation Error: Decryption key or passphrase is required.', 'error');
        document.getElementById('statusText').textContent = 'Ready';
        return;
    }

    try {
        const activeAlgo = isGcmPayload(encrypted) ? 'AES-GCM' : currentMethod;
        const decrypted = await cryptoDecrypt(activeAlgo, encrypted, key, isRawMode, iv);
        document.getElementById('result-area').value = decrypted;
        document.getElementById('statusText').textContent = 'Ready';

        const maskedKey = key.length > 4 ? key.substring(0, key.length - 4) + '****' : '****';
        lastOperation = {
            type: 'decrypt',
            algorithm: activeAlgo,
            mode: isRawMode ? 'raw' : 'passphrase',
            inputSize: encrypted.length,
            outputSize: decrypted.length,
            status: 'success',
            input: encrypted,
            output: decrypted,
            key: maskedKey
        };

        showNotification('Text decrypted successfully!', 'success');
        await saveOperation(lastOperation);
    } catch (e) {
        document.getElementById('result-area').value = e.message;
        document.getElementById('statusText').textContent = 'Ready';

        let failStatus = 'failed';
        if (e.message && e.message.includes('Authentication failed')) {
            failStatus = 'authentication_failed';
            showNotification('Decryption failed: Authentication tag verification failed. Ciphertext has been tampered with or key is incorrect.', 'error');
        } else {
            showNotification('Decryption failed: ' + e.message, 'error');
        }

        lastOperation = {
            type: 'decrypt',
            algorithm: currentMethod,
            mode: isRawMode ? 'raw' : 'passphrase',
            inputSize: encrypted.length,
            outputSize: 0,
            status: failStatus
        };
        await saveOperation(lastOperation);
    }
}

async function addCurrentOperationToAudit() {
    if (!lastOperation) {
        showNotification('No active operation to log. Perform an encryption or decryption first.', 'warning');
        return;
    }

    const meta = algorithmMetadata[lastOperation.algorithm] || { category: 'LEGACY COMPATIBILITY', badge: 'LEGACY' };
    const classification = `${meta.category} - ${meta.badge}`;

    let keyModeLabel = 'Passphrase Derived';
    if (lastOperation.mode === 'raw') {
        keyModeLabel = 'Generated Key';
    }

    let statusText = 'success';
    if (lastOperation.status === 'failed') {
        statusText = 'failed';
    } else if (lastOperation.status === 'authentication_failed') {
        statusText = 'authentication_failed';
    }

    const record = {
        id: generateOperationId(),
        timestamp: new Date().toISOString(),
        algorithm: lastOperation.algorithm,
        classification: classification,
        type: lastOperation.type,
        inputSize: lastOperation.inputSize,
        outputSize: lastOperation.outputSize,
        status: statusText,
        keyMode: keyModeLabel
    };

    if (validateAuditRecord(record)) {
        saveAuditRecord(record);
        renderAuditHistoryUI();
        showNotification('Operation metadata recorded successfully in browser history!', 'success');
        lastOperation = null;
    } else {
        showNotification('Failed to save log: Invalid schema.', 'error');
    }
}

function copyResult() {
    const result = document.getElementById('result-area').value;
    if (result.trim()) {
        navigator.clipboard.writeText(result).then(() => {
            showNotification('Copied to clipboard!', 'success');
        }).catch(err => {
            showNotification('Failed to copy to clipboard.', 'error');
        });
    } else {
        showNotification('Result area is empty.', 'warning');
    }
}

function downloadThisOperation() {
    if (!lastOperation || !lastOperation.input) {
        showNotification('Do encryption/decryption first', 'warning');
        return;
    }

    const content = `# OmniGupt Operation Log

**Operation**: ${lastOperation.type.toUpperCase()}
**Method**: ${lastOperation.algorithm}
**Key**: ${lastOperation.key}
**Timestamp**: ${new Date().toLocaleString()}

## Input
\`\`\`
${lastOperation.input}
\`\`\`

## Output
\`\`\`
${lastOperation.output}
\`\`\`

---
*Generated by OmniGupt* 🔒`;

    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `OmniGupt-${lastOperation.type}-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    showNotification('Operation downloaded as UTF-8 TXT!', 'success');
}

function clearAll() {
    ['encrypt-input', 'decrypt-input', 'result-area', 'secret-key', 'iv-input'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.value = '';
    });
    document.getElementById('statusText').textContent = 'Ready';
    updateStrength();
    if (typeof clearLab === 'function') {
        clearLab();
    }
    if (typeof clearAvalanche === 'function') {
        clearAvalanche();
    }
    showNotification('Workspace cleared', 'info');
}

// === TAMPER DETECTION LAB IMPLEMENTATION ===
let labValidPayload = '';
let labTamperedPayload = '';
let labKey = '';
let labIsRaw = false;

function toggleLabKeyView() {
    const input = document.getElementById('lab-secret-key');
    input.type = input.type === 'password' ? 'text' : 'password';
}

function genLabKey() {
    const isPassphrase = confirm('Generate secure passphrase? OK=passphrase, Cancel=raw hex key (AES-256)');
    if (isPassphrase) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
        const array = new Uint32Array(24);
        window.crypto.getRandomValues(array);
        let key = 'OmniLab-';
        for (let i = 0; i < 24; i++) {
            key += chars[array[i] % chars.length];
        }
        document.getElementById('lab-secret-key').value = key;
    } else {
        const array = new Uint8Array(32);
        window.crypto.getRandomValues(array);
        const keyHex = Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
        document.getElementById('lab-secret-key').value = keyHex;
    }
}

async function runLabEncrypt() {
    const plaintext = document.getElementById('lab-plaintext').value.trim();
    const key = document.getElementById('lab-secret-key').value.trim();
    if (!plaintext) {
        alert('Please enter a sample plaintext.');
        return;
    }
    if (!key) {
        alert('Please enter or generate a key.');
        return;
    }

    const cleanKey = key.replace(/\s/g, '');
    const isHexKey = /^[0-9a-f]{64}$/i.test(cleanKey);

    try {
        const payload = await encryptGCM(plaintext, key, isHexKey);
        labValidPayload = payload;
        labKey = key;
        labIsRaw = isHexKey;

        document.getElementById('lab-valid-payload').value = payload;
        document.getElementById('lab-tamper-btn').disabled = false;

        // Reset tampered state
        labTamperedPayload = '';
        document.getElementById('lab-tampered-payload').value = '';
        document.getElementById('lab-tamper-status').textContent = '';
        document.getElementById('lab-decrypt-btn').disabled = true;

        const resultBox = document.getElementById('lab-dec-result-box');
        if (resultBox) resultBox.style.display = 'none';
    } catch (e) {
        alert('Encryption error: ' + e.message);
    }
}

function runLabTamper() {
    if (!labValidPayload) return;

    try {
        const jsonBytes = base64ToBytes(labValidPayload);
        const jsonStr = bytesToStr(jsonBytes);
        const payload = JSON.parse(jsonStr);

        const ciphertextBytes = base64ToBytes(payload.ciphertext);
        if (ciphertextBytes.length === 0) {
            throw new Error('Empty ciphertext.');
        }

        // Modify exactly the first byte (index 0) by flipping 1 bit
        const modifiedBytes = new Uint8Array(ciphertextBytes);
        modifiedBytes[0] ^= 0x01;

        payload.ciphertext = bytesToBase64(modifiedBytes);

        const newJsonStr = JSON.stringify(payload);
        labTamperedPayload = bytesToBase64(strToBytes(newJsonStr));

        document.getElementById('lab-tampered-payload').value = labTamperedPayload;
        document.getElementById('lab-tamper-status').textContent = '⚠️ Success: Ciphertext byte at index 0 was modified (flipped 1 bit).';
        document.getElementById('lab-decrypt-btn').disabled = false;

        const resultBox = document.getElementById('lab-dec-result-box');
        if (resultBox) resultBox.style.display = 'none';
    } catch (e) {
        alert('Tampering simulation failed: ' + e.message);
    }
}

async function runLabDecrypt() {
    if (!labTamperedPayload) return;

    const resultBox = document.getElementById('lab-dec-result-box');
    const badge = document.getElementById('lab-dec-badge');
    const text = document.getElementById('lab-dec-text');
    const subtext = document.getElementById('lab-dec-subtext');

    try {
        const plaintext = await decryptGCM(labTamperedPayload, labKey, labIsRaw);

        resultBox.style.display = 'flex';
        resultBox.className = 'alert-box level-recommended';
        badge.textContent = 'SUCCESS';
        text.textContent = 'Decryption Succeeded';
        subtext.textContent = 'Result plaintext: ' + plaintext;
    } catch (e) {
        resultBox.style.display = 'flex';
        resultBox.className = 'alert-box level-danger';
        badge.textContent = 'AUTHENTICATION FAILED';
        text.textContent = 'Tampering detected. Authentication verification failed as expected.';
        subtext.textContent = 'No plaintext was returned. The Web Crypto API rejected the tampered ciphertext because the integrity tag validation failed.';
    }
}

function clearLab() {
    document.getElementById('lab-plaintext').value = 'Transfer ₹500 to User A';
    document.getElementById('lab-secret-key').value = '';
    document.getElementById('lab-valid-payload').value = '';
    document.getElementById('lab-tampered-payload').value = '';
    document.getElementById('lab-tamper-status').textContent = '';

    const resultBox = document.getElementById('lab-dec-result-box');
    if (resultBox) resultBox.style.display = 'none';

    document.getElementById('lab-tamper-btn').disabled = true;
    document.getElementById('lab-decrypt-btn').disabled = true;

    labValidPayload = '';
    labTamperedPayload = '';
    labKey = '';
    labIsRaw = false;
}

// === AVALANCHE EFFECT VISUALIZER IMPLEMENTATION ===

/**
 * Safely modifies exactly one character of the original input string.
 * Supports ASCII, Unicode, Hindi, Gujarati, and Emojis by processing code points.
 * @param {string} str - The original string.
 * @returns {string} The modified string.
 */
function safeModifyOneCharacter(str) {
    if (!str) return '';
    const codePoints = Array.from(str);
    const len = codePoints.length;
    if (len === 0) return '';
    const idx = len - 1; // alter the last character code point
    const char = codePoints[idx];
    const charCode = char.codePointAt(0);

    // Toggle case for ASCII letters
    if (/[a-zA-Z]/.test(char)) {
        if (char === char.toUpperCase()) {
            codePoints[idx] = char.toLowerCase();
        } else {
            codePoints[idx] = char.toUpperCase();
        }
    } else {
        // Increment the code point value for other characters (Unicode, Hindi, Gujarati, Emoji)
        codePoints[idx] = String.fromCodePoint(charCode + 1);
    }
    return codePoints.join('');
}

/**
 * Counts the number of set bits (1s) in a byte using Brian Kernighan's algorithm.
 * @param {number} n - The byte value.
 * @returns {number} The count of set bits.
 */
function countSetBits(n) {
    let count = 0;
    let val = n & 0xff;
    while (val) {
        val &= (val - 1);
        count++;
    }
    return count;
}

/**
 * Converts a CryptoJS WordArray to a raw Uint8Array.
 * @param {Object} wordArray - The CryptoJS WordArray.
 * @returns {Uint8Array} The raw byte array.
 */
function wordToByteArray(wordArray) {
    const words = wordArray.words;
    const sigBytes = wordArray.sigBytes;
    const u8 = new Uint8Array(sigBytes);
    let dst = 0;
    for (let i = 0; i < sigBytes; i++) {
        const byte = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
        u8[dst++] = byte;
    }
    return u8;
}

/**
 * Calculates bit-level Hamming distance and byte difference between two byte arrays.
 * Compares up to the shorter length if arrays differ in size.
 * @param {Uint8Array} arrA - The first byte array.
 * @param {Uint8Array} arrB - The second byte array.
 * @returns {Object} Comparison statistics.
 */
function calculateHammingDistance(arrA, arrB) {
    const len = Math.min(arrA.length, arrB.length);
    let changedBits = 0;
    let changedBytes = 0;

    for (let i = 0; i < len; i++) {
        const byteA = arrA[i];
        const byteB = arrB[i];
        if (byteA !== byteB) {
            changedBytes++;
        }
        const xor = byteA ^ byteB;
        changedBits += countSetBits(xor);
    }

    const totalBits = len * 8;
    const totalBytes = len;

    const bitPercentage = totalBits > 0 ? ((changedBits / totalBits) * 100) : 0;
    const bytePercentage = totalBytes > 0 ? ((changedBytes / totalBytes) * 100) : 0;

    return {
        totalBits,
        changedBits,
        bitPercentage,
        totalBytes,
        changedBytes,
        bytePercentage
    };
}

function runAvalancheChangeChar() {
    const original = document.getElementById('avalanche-original').value;
    if (!original) {
        alert('Validation Error: Original input is empty.');
        return;
    }
    const modified = safeModifyOneCharacter(original);
    document.getElementById('avalanche-modified').value = modified;
}

async function runAvalancheComparison() {
    const original = document.getElementById('avalanche-original').value;
    const modified = document.getElementById('avalanche-modified').value;

    if (!original) {
        alert('Validation Error: Original input is empty.');
        return;
    }
    if (!modified) {
        alert('Validation Error: Please modify the input text first (or click Change One Character).');
        return;
    }

    // Controlled Comparison Design Parameters
    // We derive a static key and IV purely for this comparison demonstration.
    // Static 256-bit Key (derived from 'OmniGupt Avalanche Visualizer Key Seed')
    // Static 128-bit IV (all zeros)
    const staticKey = CryptoJS.SHA256('OmniGupt Avalanche Visualizer Key Seed');
    const staticIv = CryptoJS.enc.Hex.parse('00000000000000000000000000000000');

    // Encrypt under identical educational comparison parameters (AES-256-CBC)
    const encryptedA = CryptoJS.AES.encrypt(original, staticKey, {
        iv: staticIv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });

    const encryptedB = CryptoJS.AES.encrypt(modified, staticKey, {
        iv: staticIv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });

    // Extract raw cipher text bytes
    const bytesA = wordToByteArray(encryptedA.ciphertext);
    const bytesB = wordToByteArray(encryptedB.ciphertext);

    // Run comparison metrics
    const stats = calculateHammingDistance(bytesA, bytesB);

    // Update comparison display
    document.getElementById('av-text-orig').textContent = original;
    document.getElementById('av-text-mod').textContent = modified;

    // Display hex formats
    const hexA = encryptedA.ciphertext.toString(CryptoJS.enc.Hex);
    const hexB = encryptedB.ciphertext.toString(CryptoJS.enc.Hex);
    document.getElementById('av-cipher-orig').textContent = hexA.toUpperCase();
    document.getElementById('av-cipher-mod').textContent = hexB.toUpperCase();

    // Write statistics
    document.getElementById('av-stat-total-bits').textContent = stats.totalBits;
    document.getElementById('av-stat-changed-bits').textContent = stats.changedBits;
    document.getElementById('av-stat-percentage').textContent = stats.bitPercentage.toFixed(2) + '%';

    // Render visual grid
    const grid = document.getElementById('avalanche-visual-grid');
    grid.innerHTML = ''; // clear previous grid

    // Set a safe visualization limit (e.g. 64 bytes)
    const renderLimit = 64;
    const len = Math.min(bytesA.length, bytesB.length);
    const renderLen = Math.min(len, renderLimit);

    const fragment = document.createDocumentFragment();
    for (let i = 0; i < renderLen; i++) {
        const cell = document.createElement('div');
        const byteHexA = bytesA[i].toString(16).padStart(2, '0').toUpperCase();
        const byteHexB = bytesB[i].toString(16).padStart(2, '0').toUpperCase();
        const hasChanged = bytesA[i] !== bytesB[i];

        cell.className = hasChanged ? 'byte-cell changed' : 'byte-cell';

        // Construct accessibility screen reader tags and textual markup
        const textSpan = document.createElement('span');
        textSpan.className = 'cell-text';
        textSpan.textContent = byteHexA + ' ➔ ' + byteHexB;

        const labelSpan = document.createElement('span');
        labelSpan.className = 'cell-label';
        labelSpan.textContent = hasChanged ? 'CHANGED' : `Byte ${i + 1}`;

        cell.appendChild(textSpan);
        cell.appendChild(labelSpan);

        // Add ARIA accessible descriptions
        if (hasChanged) {
            cell.setAttribute('aria-label', `Byte ${i + 1}: changed from ${byteHexA} to ${byteHexB}`);
        } else {
            cell.setAttribute('aria-label', `Byte ${i + 1}: unchanged (${byteHexA})`);
        }

        fragment.appendChild(cell);
    }

    grid.appendChild(fragment);

    // Display limit notification
    const limitText = document.getElementById('av-grid-limit-text');
    if (len > renderLimit) {
        limitText.textContent = `⚠️ Visualization limited to the first ${renderLimit} bytes for performance. Statistics include all compared output bytes.`;
        limitText.style.color = '#ffaa00';
    } else {
        limitText.textContent = `Showing all compared ciphertext output bytes.`;
        limitText.style.color = 'rgba(255, 255, 255, 0.7)';
    }

    // Display results panel
    document.getElementById('avalanche-results').style.display = 'block';
}

function clearAvalanche() {
    document.getElementById('avalanche-original').value = 'HELLO';
    document.getElementById('avalanche-modified').value = '';
    document.getElementById('avalanche-results').style.display = 'none';
    document.getElementById('avalanche-visual-grid').innerHTML = '';
}

// === AUDIT HISTORY LOG STORAGE & RENDERING ===

const ALLOWED_AUDIT_FIELDS = ['id', 'timestamp', 'algorithm', 'classification', 'type', 'inputSize', 'outputSize', 'status', 'keyMode'];

/**
 * Generates an RFC-compliant UUID (version 4) using CSPRNG.
 * Falls back to secure window.crypto.getRandomValues if randomUUID is unavailable.
 * @returns {string} The UUID.
 */
function generateOperationId() {
    if (typeof crypto.randomUUID === 'function') {
        return crypto.randomUUID();
    }
    const array = new Uint8Array(16);
    window.crypto.getRandomValues(array);
    array[6] = (array[6] & 0x0f) | 0x40;
    array[8] = (array[8] & 0x3f) | 0x80;
    return Array.from(array, (b, i) => {
        const hex = b.toString(16).padStart(2, '0');
        if (i === 4 || i === 6 || i === 8 || i === 10) {
            return '-' + hex;
        }
        return hex;
    }).join('');
}

/**
 * Validates an audit log record against an allowlist schema and prohibited fields.
 * @param {Object} record - The audit record.
 * @returns {boolean} True if valid and safe, false otherwise.
 */
function validateAuditRecord(record) {
    if (!record || typeof record !== 'object') return false;

    const keys = Object.keys(record);
    for (const key of keys) {
        if (!ALLOWED_AUDIT_FIELDS.includes(key)) {
            return false;
        }
    }

    const prohibitedFields = ['key', 'secret', 'passphrase', 'password', 'plaintext', 'ciphertext', 'input', 'output', 'decrypted'];
    for (const key of keys) {
        const normalized = key.toLowerCase().trim();
        if (prohibitedFields.includes(normalized)) {
            return false;
        }
    }

    if (typeof record.id !== 'string' || record.id.length < 10) return false;
    if (typeof record.timestamp !== 'string') return false;
    if (typeof record.algorithm !== 'string') return false;
    if (typeof record.classification !== 'string') return false;
    if (typeof record.type !== 'string') return false;
    if (typeof record.status !== 'string') return false;
    if (typeof record.keyMode !== 'string') return false;
    if (typeof record.inputSize !== 'number') return false;
    if (typeof record.outputSize !== 'number') return false;

    const allowedStatuses = ['success', 'failed', 'authentication_failed', 'invalid_input'];
    if (!allowedStatuses.includes(record.status)) return false;

    return true;
}

/**
 * Saves a single validated audit record to local storage.
 * Enforces a strict 100 record storage cap, removing the oldest records.
 * @param {Object} record - The validated record.
 */
function saveAuditRecord(record) {
    const keyName = 'omnigupt_audit_history';
    let history = { version: 2, records: [] };

    try {
        const raw = localStorage.getItem(keyName);
        if (raw) {
            const parsed = JSON.parse(raw);
            if (parsed && parsed.version === 2 && Array.isArray(parsed.records)) {
                history = parsed;
            }
        }
    } catch (e) { }

    history.records.unshift(record);
    if (history.records.length > 100) {
        history.records = history.records.slice(0, 100);
    }

    localStorage.setItem(keyName, JSON.stringify(history));
}

/**
 * Clears the local storage audit history after user confirmation.
 */
function clearAuditHistory() {
    const ok = confirm('Are you sure you want to permanently clear the local Audit History Log? This operation cannot be undone.');
    if (!ok) return;

    localStorage.removeItem('omnigupt_audit_history');
    renderAuditHistoryUI();
    document.getElementById('statusText').textContent = 'Audit History Cleared';
}

/**
 * Validates and exports the recorded audit logs as a downloadable JSON file.
 */
function exportAuditMetadata() {
    const keyName = 'omnigupt_audit_history';
    let historyObj = { version: 2, records: [] };

    try {
        const raw = localStorage.getItem(keyName);
        if (raw) {
            const parsed = JSON.parse(raw);
            if (parsed && parsed.version === 2 && Array.isArray(parsed.records)) {
                historyObj = parsed;
            }
        }
    } catch (e) { }

    const prohibitedFields = ['key', 'secret', 'passphrase', 'password', 'plaintext', 'ciphertext', 'input', 'output', 'decrypted'];
    for (const record of historyObj.records) {
        const keys = Object.keys(record);
        for (const k of keys) {
            const normalized = k.toLowerCase().trim();
            if (prohibitedFields.includes(normalized)) {
                alert(`Security Export Safety Check Blocked: Unsafe prohibited field name "${k}" detected in history records.`);
                return;
            }
        }
    }

    const jsonString = JSON.stringify(historyObj, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'omnigupt-audit-metadata.json';
    a.click();
    URL.revokeObjectURL(url);
    document.getElementById('statusText').textContent = 'Audit Metadata Exported!';
}

/**
 * Audits, sanitizes, and migrates legacy local storage logging parameters. Wipes records with secrets.
 */
function migrateLegacyAuditStorage() {
    const keyName = 'omnigupt_audit_history';
    const legacyKeyName = 'omni_logs';

    const rawHistory = localStorage.getItem(keyName) || localStorage.getItem(legacyKeyName);
    if (!rawHistory) return;

    try {
        const parsed = JSON.parse(rawHistory);
        if (!parsed || parsed.version !== 2 || !Array.isArray(parsed.records)) {
            localStorage.removeItem(keyName);
            localStorage.removeItem(legacyKeyName);
            return;
        }

        const safeRecords = [];
        const prohibitedFields = ['key', 'secret', 'passphrase', 'password', 'plaintext', 'ciphertext', 'input', 'output', 'decrypted'];

        for (const record of parsed.records) {
            let isSafe = true;
            const keys = Object.keys(record);
            for (const k of keys) {
                if (prohibitedFields.includes(k.toLowerCase().trim())) {
                    isSafe = false;
                    break;
                }
            }
            if (isSafe && validateAuditRecord(record)) {
                safeRecords.push(record);
            }
        }

        const newHistory = {
            version: 2,
            records: safeRecords.slice(0, 100)
        };
        localStorage.setItem(keyName, JSON.stringify(newHistory));
        if (localStorage.getItem(legacyKeyName)) {
            localStorage.removeItem(legacyKeyName);
        }
    } catch (e) {
        localStorage.removeItem(keyName);
        localStorage.removeItem(legacyKeyName);
    }
}

/**
 * Safely renders the Audit History Log table using textContent to mitigate stored XSS.
 */
function renderAuditHistoryUI() {
    const rowsContainer = document.getElementById('audit-history-rows');
    if (!rowsContainer) return;

    rowsContainer.innerHTML = '';

    const keyName = 'omnigupt_audit_history';
    let records = [];

    try {
        const raw = localStorage.getItem(keyName);
        if (raw) {
            const parsed = JSON.parse(raw);
            if (parsed && parsed.version === 2 && Array.isArray(parsed.records)) {
                records = parsed.records;
            }
        }
    } catch (e) { }

    if (records.length === 0) {
        const row = document.createElement('tr');
        const cell = document.createElement('td');
        cell.setAttribute('colspan', '7');
        cell.style.textAlign = 'center';
        cell.style.opacity = '0.7';
        cell.textContent = 'No operation metadata recorded yet.';
        row.appendChild(cell);
        rowsContainer.appendChild(row);
        return;
    }

    const fragment = document.createDocumentFragment();
    for (const r of records) {
        const row = document.createElement('tr');

        const timeCell = document.createElement('td');
        timeCell.style.padding = '12px';
        try {
            timeCell.textContent = new Date(r.timestamp).toLocaleString();
        } catch (e) {
            timeCell.textContent = r.timestamp;
        }

        const algoCell = document.createElement('td');
        algoCell.style.padding = '12px';
        algoCell.textContent = r.algorithm;

        const classCell = document.createElement('td');
        classCell.style.padding = '12px';
        classCell.textContent = r.classification;

        const typeCell = document.createElement('td');
        typeCell.style.padding = '12px';
        typeCell.style.textTransform = 'uppercase';
        typeCell.textContent = r.type;

        const inCell = document.createElement('td');
        inCell.style.padding = '12px';
        inCell.textContent = r.inputSize;

        const outCell = document.createElement('td');
        outCell.style.padding = '12px';
        outCell.textContent = r.outputSize;

        const statusCell = document.createElement('td');
        statusCell.style.padding = '12px';
        statusCell.style.fontWeight = 'bold';

        if (r.status === 'success') {
            statusCell.style.color = '#00ff88';
            statusCell.textContent = 'SUCCESS';
        } else if (r.status === 'authentication_failed') {
            statusCell.style.color = '#ff0055';
            statusCell.textContent = 'AUTH FAILED';
        } else {
            statusCell.style.color = '#ffaa00';
            statusCell.textContent = 'FAILED';
        }

        row.appendChild(timeCell);
        row.appendChild(algoCell);
        row.appendChild(classCell);
        row.appendChild(typeCell);
        row.appendChild(inCell);
        row.appendChild(outCell);
        row.appendChild(statusCell);

        fragment.appendChild(row);
    }

    rowsContainer.appendChild(fragment);
}

// Method buttons
document.querySelectorAll('.method-btn-card').forEach(btn => {
    btn.addEventListener('click', (e) => {
        e.preventDefault();
        setActiveButton(btn.dataset.method);
    });
});

// Backend status indicator
setInterval(testBackend, 5000);

// Tab Switching Layout Logic
function switchTab(tabName) {
    const tabs = ['crypto-tool', 'security-lab', 'audit-history', 'about', 'cipher-sense'];
    tabs.forEach(t => {
        const btn = document.getElementById(`tab-${t}`);
        const view = document.getElementById(`view-${t}`);
        if (t === tabName) {
            if (btn) {
                btn.classList.add('cyber-tab--active');
                btn.setAttribute('aria-selected', 'true');
            }
            if (view) {
                view.style.display = 'block';
                view.classList.add('cyber-tabs__panel--active');
            }
        } else {
            if (btn) {
                btn.classList.remove('cyber-tab--active');
                btn.setAttribute('aria-selected', 'false');
            }
            if (view) {
                view.style.display = 'none';
                view.classList.remove('cyber-tabs__panel--active');
            }
        }
    });
}

// Key Mode Switching Logic
function setKeyMode(mode) {
    const isPassphrase = (mode === 'passphrase');
    isRawMode = !isPassphrase;

    const passphraseBtn = document.getElementById('mode-passphrase');
    const rawBtn = document.getElementById('mode-raw');
    const keyLabel = document.getElementById('key-input-label');
    const keyInput = document.getElementById('secret-key');
    const keyGenBtn = document.getElementById('key-gen-btn');
    const ivSection = document.getElementById('iv-section');

    if (passphraseBtn && rawBtn) {
        passphraseBtn.classList.toggle('active', isPassphrase);
        rawBtn.classList.toggle('active', !isPassphrase);
    }

    if (keyLabel) {
        keyLabel.textContent = isPassphrase ? '🔑 Passphrase' : '🔑 Hex Key';
    }

    if (keyInput) {
        keyInput.placeholder = isPassphrase ? 'Enter passphrase...' : 'Enter 32/64 hex key...';
    }

    if (keyGenBtn) {
        keyGenBtn.style.display = isPassphrase ? 'none' : 'block';
    }

    if (ivSection) {
        ivSection.style.display = (isRawMode && currentMethod === 'AES') ? 'block' : 'none';
    }

    updateStrength();
    updateAdvancedSettingsUI();
}

// Dynamic Parameter Details Update
function updateAdvancedSettingsUI() {
    const advAlgo = document.getElementById('adv-algo');
    const advKeysize = document.getElementById('adv-keysize');
    const advMode = document.getElementById('adv-mode');
    const advKdf = document.getElementById('adv-kdf');
    const advIterations = document.getElementById('adv-iterations');

    if (!advAlgo) return;

    if (currentMethod === 'AES-GCM') {
        advAlgo.textContent = 'AES-256-GCM';
        advKeysize.textContent = '256 bits';
        advMode.textContent = 'GCM (Galois/Counter Mode)';
        advKdf.textContent = isRawMode ? 'Direct (No KDF)' : 'PBKDF2-HMAC-SHA256';
        advIterations.textContent = isRawMode ? 'N/A' : '600,000';
    } else if (currentMethod === 'AES') {
        advAlgo.textContent = 'AES-256-CBC';
        advKeysize.textContent = '256 bits';
        advMode.textContent = 'CBC (Cipher Block Chaining)';
        advKdf.textContent = isRawMode ? 'Direct (No KDF)' : 'CryptoJS Key Derivation';
        advIterations.textContent = isRawMode ? 'N/A' : '1 (CryptoJS default)';
    } else if (currentMethod === 'DES') {
        advAlgo.textContent = 'DES';
        advKeysize.textContent = '56 bits';
        advMode.textContent = 'CBC (CryptoJS default)';
        advKdf.textContent = 'CryptoJS Key Derivation';
        advIterations.textContent = '1 (CryptoJS default)';
    } else if (currentMethod === 'TripleDES') {
        advAlgo.textContent = 'Triple DES (3DES)';
        advKeysize.textContent = '168 bits';
        advMode.textContent = 'CBC (CryptoJS default)';
        advKdf.textContent = 'CryptoJS Key Derivation';
        advIterations.textContent = '1 (CryptoJS default)';
    } else if (currentMethod === 'Rabbit') {
        advAlgo.textContent = 'Rabbit Stream Cipher';
        advKeysize.textContent = '128 bits';
        advMode.textContent = 'Stream Mode';
        advKdf.textContent = 'CryptoJS Key Derivation';
        advIterations.textContent = '1 (CryptoJS default)';
    }
}

// Lightweight Toast Notification Engine
function showNotification(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    // Add type indicator emoji
    let emoji = 'ℹ️';
    if (type === 'success') emoji = '✅';
    if (type === 'error') emoji = '❌';
    if (type === 'warning') emoji = '⚠️';

    const msgSpan = document.createElement('span');
    msgSpan.textContent = `${emoji} ${message}`;
    toast.appendChild(msgSpan);

    container.appendChild(toast);

    // Fade out and remove after 1.5s
    setTimeout(() => {
        toast.classList.add('fade-out');
        toast.addEventListener('transitionend', () => {
            toast.remove();
        });
        // Fallback removal if transitionend doesn't fire
        setTimeout(() => toast.remove(), 500);
    }, 1500);
}

// Export to global scope for inline event handlers
window.switchTab = switchTab;
window.setKeyMode = setKeyMode;
window.showNotification = showNotification;
window.updateAdvancedSettingsUI = updateAdvancedSettingsUI;
window.encryptText = encryptText;
window.decryptText = decryptText;
window.downloadThisOperation = downloadThisOperation;
window.copyResult = copyResult;
window.clearAll = clearAll;
window.genKey = genKey;
window.toggleKeyView = toggleKeyView;
// Exported for CipherSense decryption reuse (no duplication of crypto logic)
window.cryptoDecrypt = cryptoDecrypt;
window.decryptGCM = decryptGCM;
