// OmniGupt Pro - SINGLE Operation Download + Clean Inter Font

import { decrypt as cryptoDecrypt, encrypt as cryptoEncrypt, checkKeyStrength, generateKey } from './crypto.js';

let currentMethod = 'AES';
let isRawMode = false;
let lastOperation = null;

document.addEventListener('DOMContentLoaded', () => {
    setActiveButton('AES');
    document.getElementById('secret-key').addEventListener('input', updateStrength);
    document.querySelectorAll('.method-btn').forEach(btn => btn.addEventListener('click', () => setActiveButton(btn.dataset.method)));
    updateStrength(); // Init strength
});

function setActiveButton(method) {
    currentMethod = method;
    document.querySelectorAll('.method-btn').forEach(btn => btn.classList.toggle('active', btn.dataset.method === method));
    document.getElementById('statusText').textContent = `${method} Active`;
}

function updateStrength() {
    const key = document.getElementById('secret-key').value;
    const ivEl = document.getElementById('iv-input');
    const modeIndicator = document.getElementById('mode-indicator');
    
    // Auto-detect raw mode from key format (hex)
    const isHexKey = /^[0-9a-f]{32,64}$/i.test(key.replace(/\\s/g, ''));
    isRawMode = isHexKey || (ivEl && ivEl.value.trim());
    
    const strength = checkKeyStrength(key, isRawMode);
    const text = document.getElementById('strengthText');
    
    if (typeof window.updateStrengthVisual === 'function') {
        const percentage = Math.max(0, Math.min(100, Number(strength.score) || 0));
        window.updateStrengthVisual(percentage);
    } else {
        const bar = document.getElementById('barFill');
        if (bar) {
            bar.style.width = strength.score + '%';
            bar.style.background = strength.color;
        }
    }
    
    if (text) {
        text.textContent = `${strength.label} (${strength.score}%)`;
    }
    
    // Update mode indicator
    if (modeIndicator) {
        modeIndicator.textContent = isRawMode ? '🔧 RAW AES' : '';
        modeIndicator.style.color = isRawMode ? '#ffaa00' : '#39ff14';
    }
    
    // Show/hide IV section
    const ivSection = document.getElementById('iv-section');
    if (ivSection) {
        ivSection.style.display = isRawMode ? 'block' : 'none';
    }
}

function toggleKeyView() {
    const input = document.getElementById('secret-key');
    input.type = input.type === 'password' ? 'text' : 'password';
}

function genKey() {
    const isPassphrase = confirm('Generate secure passphrase? OK=passphrase, Cancel=raw hex key (AES-256)');
    if (isPassphrase) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
        const array = new Uint32Array(24);
        window.crypto.getRandomValues(array);
        let key = 'OmniGupt-';
        for (let i = 0; i < 24; i++) {
            key += chars[array[i] % chars.length];
        }
        document.getElementById('secret-key').value = key;
    } else {
        // Generate secure 256-bit hex key (32 bytes = 64 hex chars)
        const array = new Uint8Array(32);
        window.crypto.getRandomValues(array);
        const keyHex = Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
        document.getElementById('secret-key').value = keyHex;
    }
    updateStrength();
}

async function encryptText() {
    const text = document.getElementById('encrypt-input').value.trim();
    const key = document.getElementById('secret-key').value.trim() || 'OmniGuptDefault';
    
    if (!text) {
        document.getElementById('statusText').textContent = 'Enter text first';
        return;
    }
    
    try {
        const encrypted = await cryptoEncrypt(currentMethod, text, key);
        document.getElementById('result-area').value = encrypted;
        document.getElementById('statusText').textContent = `Encrypted with ${currentMethod}`;
        const maskedKey = key.length > 4 ? key.substring(0, key.length - 4) + '****' : '****';
        lastOperation = { type: 'encrypt', input: text, output: encrypted, key: maskedKey, method: currentMethod };
        const dlInfo = document.querySelector('.download-info');
        if (dlInfo) dlInfo.textContent = 'Operation logged - Ready to download';
    } catch(e) {
        document.getElementById('result-area').value = 'Encryption error';
    }
}

async function decryptText() {
    const encrypted = document.getElementById('decrypt-input').value.trim();
    const key = document.getElementById('secret-key').value.trim() || 'OmniGuptDefault';
    const iv = document.getElementById('iv-input')?.value.trim() || null;
    
    if (!encrypted) {
        document.getElementById('statusText').textContent = 'Enter encrypted text';
        return;
    }
    
    try {
        const decrypted = await cryptoDecrypt(currentMethod, encrypted, key, isRawMode, iv);
        document.getElementById('result-area').value = decrypted;
        const modeDisplay = isRawMode ? 'Raw AES' : currentMethod;
        document.getElementById('statusText').textContent = `Decrypted with ${modeDisplay}`;
        const maskedKey = key.length > 4 ? key.substring(0, key.length - 4) + '****' : '****';
        lastOperation = { type: 'decrypt', input: encrypted, output: decrypted, key: maskedKey, method: `${modeDisplay} ${isRawMode ? '(IV:' + (iv||'auto') + ')' : ''}` };
        const dlInfo = document.querySelector('.download-info');
        if (dlInfo) dlInfo.textContent = 'Operation logged - Ready to download';
    } catch(e) {
        document.getElementById('result-area').value = `Decryption failed: ${e.message}. Try different key/IV/mode.`;
    }
}

function downloadThisOperation() {
    if (!lastOperation) {
        alert('Do encryption/decryption first');
        return;
    }
    
    const content = `# OmniGupt Operation Log

**Operation**: ${lastOperation.type.toUpperCase()}
**Method**: ${lastOperation.method}
**Key**: ${lastOperation.key} (hidden)
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
    document.getElementById('statusText').textContent = 'Operation downloaded as UTF-8 TXT!';
}

function copyResult() {
    const result = document.getElementById('result-area').value;
    if (result.trim()) {
        navigator.clipboard.writeText(result).then(() => {
            document.getElementById('statusText').textContent = 'Result copied!';
            setTimeout(() => document.getElementById('statusText').textContent = 'Ready', 1500);
        });
    }
}

function clearAll() {
    ['encrypt-input', 'decrypt-input', 'result-area', 'secret-key'].forEach(id => document.getElementById(id).value = '');
    document.getElementById('statusText').textContent = 'Cleared';
    document.querySelector('.download-info').textContent = 'Last operation logged';
    updateStrength();
}

// Method button clicks
document.querySelectorAll('.method-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
        e.preventDefault();
        setActiveButton(btn.dataset.method);
    });
});

