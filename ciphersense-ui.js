/**
 * CipherSense UI — Crypto Format Analyzer
 * OmniGupt | Renders results using the existing coffee theme design system
 *
 * No Math.random(), no fetch, no localStorage of analyzed input.
 */

'use strict';

// ============================================================
// UI STATE
// ============================================================
let _csCurrentResults = [];
let _csCurrentFeatures = null;
let _csShowingAll = false;
const CS_INITIAL_RESULTS = 5;

// ============================================================
// CATEGORY BADGE CONFIG (matches coffee theme palette)
// ============================================================
const CS_CATEGORY_STYLES = {
    HASH:                 { label: 'HASH',               color: '#C98B5F' },
    PASSWORD_HASH:        { label: 'PASSWORD HASH',       color: '#D96C6C' },
    ENCODING:             { label: 'ENCODING',            color: '#8DA982' },
    ENCRYPTION_FORMAT:    { label: 'ENCRYPTION',          color: '#A86F45' },
    CIPHERTEXT_CANDIDATE: { label: 'CIPHERTEXT?',         color: '#E6C894' },
    TOKEN:                { label: 'TOKEN',               color: '#D7B899' },
    KEY_OR_CERTIFICATE:   { label: 'KEY / CERT',          color: '#C98B5F' },
    UNKNOWN:              { label: 'UNKNOWN',             color: '#5C4033' }
};

// ============================================================
// RENDER ANALYSIS SUMMARY
// ============================================================
function cs_renderSummary(features) {
    const el = document.getElementById('cs-summary');
    if (!el || !features) return;

    const categorySignal = features.categorySignal || 'Unknown';

    const charTypes = [];
    if (features.hasUpper) charTypes.push('Uppercase');
    if (features.hasLower) charTypes.push('Lowercase');
    if (features.hasDigit) charTypes.push('Digits');
    if (features.hasSymbol) charTypes.push('Symbols');

    el.innerHTML = `
        <div class="cs-summary-grid">
            <div class="cs-summary-stat">
                <span class="cs-stat-label">Input Length</span>
                <span class="cs-stat-value">${features.length} chars</span>
            </div>
            <div class="cs-summary-stat">
                <span class="cs-stat-label">Representation</span>
                <span class="cs-stat-value">${features.isStrictHex ? 'Hexadecimal' : features.isCanonicalBase64 ? 'Base64' : features.isBase64URL ? 'Base64URL' : features.isBinaryText ? 'Binary' : 'Mixed/Text'}</span>
            </div>
            <div class="cs-summary-stat">
                <span class="cs-stat-label">Estimated Bytes</span>
                <span class="cs-stat-value">${features.hexByteLen !== null ? features.hexByteLen + ' bytes' : features.base64ByteLength !== null ? '~' + features.base64ByteLength + ' bytes' : 'N/A'}</span>
            </div>
            <div class="cs-summary-stat">
                <span class="cs-stat-label">Shannon Entropy</span>
                <span class="cs-stat-value">${features.entropy} bits/char</span>
            </div>
            <div class="cs-summary-stat">
                <span class="cs-stat-label">Unique Characters</span>
                <span class="cs-stat-value">${features.uniqueChars}</span>
            </div>
            <div class="cs-summary-stat">
                <span class="cs-stat-label">Char Types</span>
                <span class="cs-stat-value">${charTypes.join(', ') || 'N/A'}</span>
            </div>
            <div class="cs-summary-stat">
                <span class="cs-stat-label">Structure</span>
                <span class="cs-stat-value">${features.isJWT ? '3-segment JWT' : features.colonSegments.length === 2 ? 'Colon-separated' : features.dollarCount >= 2 ? 'Dollar-separated ($)' : 'Fixed-length'}</span>
            </div>
            <div class="cs-summary-stat">
                <span class="cs-stat-label">Category Signal</span>
                <span class="cs-stat-value cs-stat-accent">${categorySignal}</span>
            </div>
        </div>
    `;
}

// ============================================================
// RENDER RANKED RESULTS
// ============================================================
function cs_renderResults(results, showAll = false) {
    const el = document.getElementById('cs-results');
    if (!el) return;

    if (!results || results.length === 0) {
        el.innerHTML = `
            <div class="cs-empty-state">
                <div class="cs-empty-icon">🔍</div>
                <p>No recognizable cryptographic patterns found.</p>
                <p class="cs-muted">Try a different input or check the format.</p>
            </div>
        `;
        return;
    }

    const toShow = showAll ? results : results.slice(0, CS_INITIAL_RESULTS);
    const hasMore = results.length > CS_INITIAL_RESULTS && !showAll;

    let html = '<div class="cs-results-list">';

    toShow.forEach((result, idx) => {
        const catStyle = CS_CATEGORY_STYLES[result.category] || CS_CATEGORY_STYLES.UNKNOWN;
        const positiveEvidence = result.evidence.filter(e => e.type === 'positive');
        const actions = window.cipherSense.resolveAction(result);

        html += `
        <div class="cs-result-card ${idx === 0 ? 'cs-result-card--top' : ''}" data-result-id="${result.id}">
            <div class="cs-result-header">
                <div class="cs-result-title-row">
                    <span class="cs-result-name">${cs_escapeHtml(result.displayName)}</span>
                    <span class="cs-category-badge" style="background: ${catStyle.color}22; border-color: ${catStyle.color}; color: ${catStyle.color}">
                        ${catStyle.label}
                    </span>
                    ${result.isDeterministic ? '<span class="cs-det-badge" title="Deterministic signature — high confidence match">✓ DETERMINISTIC</span>' : ''}
                    ${result.sensitiveWarning ? '<span class="cs-warn-badge">⚠ SENSITIVE</span>' : ''}
                </div>
                <div class="cs-confidence-row">
                    <div class="cs-confidence-bar-wrap" role="progressbar" aria-valuenow="${result.score}" aria-valuemin="0" aria-valuemax="100" aria-label="${result.score}% confidence">
                        <div class="cs-confidence-bar-fill" style="width: ${result.score}%"></div>
                    </div>
                    <span class="cs-confidence-pct">${result.score}%</span>
                    <button class="cs-tooltip-btn" aria-label="What does confidence mean?" onclick="cs_showConfidenceInfo()">ⓘ</button>
                </div>
                <p class="cs-result-desc">${cs_escapeHtml(result.description)}</p>
            </div>

            <div class="cs-result-body">
                <button class="cs-expand-btn" onclick="cs_toggleEvidence('${result.id}')" aria-expanded="false" aria-controls="cs-evidence-${result.id}">
                    📋 View Evidence (${result.evidence.length} points)
                    <span class="cs-expand-icon">▼</span>
                </button>

                <div class="cs-evidence-panel" id="cs-evidence-${result.id}" hidden>
                    <div class="cs-evidence-title">Why this matched:</div>
                    ${result.evidence.map(ev => `
                        <div class="cs-evidence-item cs-evidence-${ev.type}">
                            <span class="cs-evidence-icon">${ev.type === 'positive' ? '✓' : ev.type === 'ambiguity' ? '⚠' : '✗'}</span>
                            <span>${cs_escapeHtml(ev.text)}</span>
                        </div>
                    `).join('')}
                    <p class="cs-evidence-note">
                        Confidence represents signature and heuristic match strength. It is not a guarantee of the exact cryptographic algorithm.
                    </p>
                </div>

                ${actions.length > 0 ? `
                <div class="cs-action-row">
                    ${actions.map(action => `
                        <button class="btn-cyber cs-action-btn"
                            onclick="cs_handleAction('${result.id}', '${action.type}')"
                            aria-label="${cs_escapeHtml(action.label)}">
                            ${cs_escapeHtml(action.label)}
                        </button>
                    `).join('')}
                </div>
                ` : ''}

                <div class="cs-action-panel" id="cs-action-panel-${result.id}" hidden></div>
            </div>
        </div>
        `;
    });

    html += '</div>';

    if (hasMore) {
        html += `
        <button class="btn-cyber cs-show-more-btn" onclick="cs_showAllResults()">
            Show ${results.length - CS_INITIAL_RESULTS} More Possibilities ▼
        </button>
        `;
    }

    el.innerHTML = html;
}

// ============================================================
// TOGGLE EVIDENCE PANEL
// ============================================================
function cs_toggleEvidence(resultId) {
    const panel = document.getElementById(`cs-evidence-${resultId}`);
    const btn = panel ? panel.previousElementSibling : null;
    if (!panel) return;
    const isHidden = panel.hidden;
    panel.hidden = !isHidden;
    if (btn) {
        btn.setAttribute('aria-expanded', String(isHidden));
        btn.querySelector('.cs-expand-icon').textContent = isHidden ? '▲' : '▼';
    }
}

// ============================================================
// HANDLE ACTION (DECODE / INSPECT / DECRYPT)
// ============================================================
function cs_handleAction(resultId, actionType) {
    const result = _csCurrentResults.find(r => r.id === resultId);
    const features = _csCurrentFeatures;
    const rawValue = features ? features.raw : '';
    const panelEl = document.getElementById(`cs-action-panel-${resultId}`);
    if (!panelEl || !result || !features) return;

    panelEl.hidden = false;

    if (actionType === 'decode') {
        cs_renderDecodePanel(panelEl, rawValue, result);
    } else if (actionType === 'hash-info') {
        cs_renderHashInfoPanel(panelEl, result);
    } else if (actionType === 'token-inspect') {
        cs_renderJWTPanel(panelEl, rawValue);
    } else if (actionType === 'structure-inspect') {
        cs_renderStructurePanel(panelEl, rawValue, features, result);
    } else if (actionType === 'decrypt-config') {
        cs_renderDecryptConfigPanel(panelEl, result, rawValue);
    }
}

// ── DECODE PANEL ──────────────────────────────────────────
function cs_renderDecodePanel(el, value, result) {
    const chain = window.cipherSense.decodeRecursive(value, 0);

    let html = '<div class="cs-action-content">';
    html += '<h4 class="cs-action-title">🔓 Decoded Output</h4>';

    if (chain.length === 0) {
        html += '<p class="cs-muted">Could not decode this value.</p>';
    } else {
        html += '<div class="cs-decode-chain">';
        chain.forEach((step, i) => {
            html += `
            <div class="cs-decode-step">
                ${i > 0 ? '<div class="cs-chain-arrow">↓</div>' : ''}
                <div class="cs-decode-step-label">${cs_escapeHtml(step.label)}</div>
                <div class="cs-decode-output">
                    <code class="cs-output-code">${cs_escapeHtml(String(step.decoded || ''))}</code>
                    <button class="cyber-btn cyber-btn--sm cs-copy-btn"
                        onclick="cs_copyText(${JSON.stringify(String(step.decoded || ''))})"
                        aria-label="Copy decoded value">📋 Copy</button>
                </div>
            </div>
            `;
        });
        html += '</div>';
    }

    html += '</div>';
    el.innerHTML = html;
}

// ── HASH INFO PANEL ───────────────────────────────────────
function cs_renderHashInfoPanel(el, result) {
    el.innerHTML = `
    <div class="cs-action-content cs-hash-info">
        <h4 class="cs-action-title">🔐 Hash Analysis</h4>
        <div class="cs-info-alert cs-info-alert--info">
            <strong>One-way cryptographic function</strong><br>
            ${cs_escapeHtml(result.category === 'PASSWORD_HASH' ?
                'Password hashes are designed to be computationally irreversible. Direct decryption is not possible.' :
                'Hash functions are one-way transforms. The original input cannot be mathematically recovered from the hash output alone.'
            )}
        </div>
        <p class="cs-muted" style="margin-top:var(--space-sm);">
            ${result.category === 'PASSWORD_HASH' ?
                'CipherSense does not implement password cracking, dictionary attacks, or brute-force. This tool is for analysis and education only.' :
                'CipherSense does not implement preimage attacks or rainbow table lookups.'
            }
        </p>
    </div>
    `;
}

// ── JWT PANEL ─────────────────────────────────────────────
function cs_renderJWTPanel(el, value) {
    const decoded = window.cipherSense.decodeJWT(value);
    if (!decoded) {
        el.innerHTML = '<div class="cs-action-content"><p class="cs-muted">Could not decode JWT segments.</p></div>';
        return;
    }

    const { header, payload } = decoded;

    const formatClaim = (key, val) => {
        const claimDesc = { iss: 'Issuer', sub: 'Subject', aud: 'Audience', exp: 'Expiry', nbf: 'Not Before', iat: 'Issued At', jti: 'JWT ID' };
        if (key === 'exp' || key === 'nbf' || key === 'iat') {
            try {
                const date = new Date(val * 1000).toISOString();
                return `${claimDesc[key] || key}: <strong>${val}</strong> <span class="cs-muted">(${date})</span>`;
            } catch(e) {}
        }
        return `${claimDesc[key] || key}: <strong>${cs_escapeHtml(String(val))}</strong>`;
    };

    el.innerHTML = `
    <div class="cs-action-content">
        <h4 class="cs-action-title">🔍 JWT Inspector</h4>
        <div class="cs-info-alert cs-info-alert--warn">
            ⚠ Decoded does not mean verified. CipherSense has not validated the signature.
        </div>
        <div class="cs-jwt-section">
            <div class="cs-jwt-label">Header</div>
            <div class="cs-jwt-block">
                <div>Algorithm: <strong>${cs_escapeHtml(header.alg || 'N/A')}</strong></div>
                <div>Type: <strong>${cs_escapeHtml(header.typ || 'N/A')}</strong></div>
                ${Object.entries(header).filter(([k]) => !['alg','typ'].includes(k)).map(([k,v]) => `<div>${cs_escapeHtml(k)}: <strong>${cs_escapeHtml(String(v))}</strong></div>`).join('')}
            </div>
        </div>
        <div class="cs-jwt-section">
            <div class="cs-jwt-label">Payload Claims</div>
            <div class="cs-jwt-block">
                ${Object.entries(payload).map(([k,v]) => `<div>${formatClaim(k, v)}</div>`).join('')}
            </div>
        </div>
        <div class="cs-jwt-section">
            <div class="cs-jwt-label">Signature</div>
            <div class="cs-jwt-block cs-jwt-sig">
                <code>${cs_escapeHtml(decoded.signatureB64.substring(0, 60))}${decoded.signatureB64.length > 60 ? '…' : ''}</code>
                <p class="cs-muted">Signature verification requires a matching public key or secret.</p>
            </div>
        </div>
    </div>
    `;
}

// ── STRUCTURE PANEL ───────────────────────────────────────
function cs_renderStructurePanel(el, value, features, result) {
    if (features.isPEM) {
        const pem = window.cipherSense.inspectPEM(value);
        el.innerHTML = `
        <div class="cs-action-content">
            <h4 class="cs-action-title">🔑 PEM Structure</h4>
            ${pem && pem.isSensitive ? `
            <div class="cs-info-alert cs-info-alert--error">
                ⚠ SENSITIVE: Private key material detected. Analysis is performed locally. Never share private keys.
            </div>` : ''}
            <div class="cs-jwt-block">
                <div>Container Type: <strong>${cs_escapeHtml(pem ? pem.type : 'Unknown')}</strong></div>
                <div>Data Lines: <strong>${cs_escapeHtml(String(pem ? pem.lineCount : 'N/A'))}</strong></div>
            </div>
        </div>`;
        return;
    }

    if (features.isOpenSSLSalted) {
        el.innerHTML = `
        <div class="cs-action-content">
            <h4 class="cs-action-title">🧂 OpenSSL Salted Format</h4>
            <div class="cs-jwt-block">
                <div>Format: <strong>OpenSSL enc (Salted__)</strong></div>
                <div>Salt: <code>${cs_escapeHtml(features.openSSLSalt || 'N/A')}</code></div>
                <div>Cipher: <strong>Unknown (not embedded in header)</strong></div>
            </div>
            <p class="cs-muted" style="margin-top:var(--space-sm);">Compatible ciphers include AES-256-CBC, AES-128-CBC, and others depending on OpenSSL invocation parameters.</p>
        </div>`;
        return;
    }

    // Generic high-entropy
    el.innerHTML = `
    <div class="cs-action-content">
        <h4 class="cs-action-title">📊 Structure Analysis</h4>
        <div class="cs-jwt-block">
            <div>Length: <strong>${features.length} chars</strong></div>
            <div>Entropy: <strong>${features.entropy} bits/char</strong></div>
            ${features.hexByteLen !== null ? `<div>Byte length: <strong>${features.hexByteLen} bytes</strong></div>` : ''}
            ${features.aesBlockAligned ? '<div>AES block-aligned: <strong>Yes (multiple of 16 bytes)</strong></div>' : ''}
        </div>
        <p class="cs-muted" style="margin-top:var(--space-sm);">Ciphertext alone cannot uniquely identify an encryption algorithm. Key size, cipher mode, and padding are not visible in the output.</p>
    </div>`;
}

// ── DECRYPT CONFIG PANEL ──────────────────────────────────
function cs_renderDecryptConfigPanel(el, result, rawValue) {
    let formHtml = '';
    const params = result.decryptionParams || [];

    const isOmniGCM = result.id === 'omnigupt-aes-gcm';
    const isCryptoJSLegacy = result.id === 'cryptojs-legacy-salted';
    const isAESCBC = result.id === 'aes-cbc-iv-ciphertext';

    if (isOmniGCM) {
        formHtml = `
            <div class="cs-form-group">
                <label class="cs-form-label" for="cs-dec-key-gcm">Passphrase or Raw Hex Key</label>
                <div style="display:flex; gap:var(--space-xs)">
                    <input type="password" id="cs-dec-key-gcm" class="cyber-input" placeholder="Enter passphrase or 64-char hex key…" autocomplete="off"/>
                    <button type="button" class="cyber-btn cyber-btn--sm" onclick="cs_toggleDecInput('cs-dec-key-gcm')" aria-label="Toggle visibility">👁</button>
                </div>
            </div>
            <button class="btn-cyber" onclick="cs_doOmniGuptDecrypt('${result.id}', '${cs_escapeHtml(rawValue.replace(/'/g, "\\'"))}')">[ ATTEMPT DECRYPTION ]</button>
        `;
    } else if (isCryptoJSLegacy) {
        formHtml = `
            <div class="cs-form-group">
                <label class="cs-form-label" for="cs-dec-pass-cjs">Passphrase</label>
                <div style="display:flex; gap:var(--space-xs)">
                    <input type="password" id="cs-dec-pass-cjs" class="cyber-input" placeholder="Enter passphrase…" autocomplete="off"/>
                    <button type="button" class="cyber-btn cyber-btn--sm" onclick="cs_toggleDecInput('cs-dec-pass-cjs')" aria-label="Toggle visibility">👁</button>
                </div>
            </div>
            <div class="cs-form-group">
                <label class="cs-form-label" for="cs-dec-algo-cjs">Cipher</label>
                <select id="cs-dec-algo-cjs" class="cyber-input">
                    <option value="AES">AES</option>
                    <option value="DES">DES</option>
                    <option value="TripleDES">Triple DES (3DES)</option>
                    <option value="Rabbit">Rabbit</option>
                </select>
            </div>
            <button class="btn-cyber" onclick="cs_doCryptoJSDecrypt('${result.id}')">[ ATTEMPT DECRYPTION ]</button>
        `;
    } else if (isAESCBC) {
        const colonIdx = rawValue.indexOf(':');
        const autoIV = colonIdx > 0 ? rawValue.substring(0, colonIdx) : '';
        formHtml = `
            <div class="cs-form-group">
                <label class="cs-form-label" for="cs-dec-key-aes">Raw Hex Key (32 or 64 hex chars)</label>
                <input type="text" id="cs-dec-key-aes" class="cyber-input" placeholder="32 or 64 hex chars..." autocomplete="off"/>
            </div>
            <div class="cs-form-group">
                <label class="cs-form-label" for="cs-dec-iv-aes">IV (auto-detected: ${autoIV || 'none'})</label>
                <input type="text" id="cs-dec-iv-aes" class="cyber-input" value="${autoIV}" placeholder="32 hex chars (optional)"/>
            </div>
            <button class="btn-cyber" onclick="cs_doAESCBCDecrypt('${result.id}', '${cs_escapeHtml(rawValue.replace(/'/g, "\\'"))}')">[ ATTEMPT DECRYPTION ]</button>
        `;
    }

    el.innerHTML = `
    <div class="cs-action-content">
        <h4 class="cs-action-title">🔑 Configure Decryption</h4>
        <div class="cs-info-alert cs-info-alert--info">
            All decryption is performed locally in your browser. Parameters are not stored or transmitted.
        </div>
        <div class="cs-decrypt-form">
            ${formHtml}
        </div>
        <div id="cs-decrypt-result-${result.id}" class="cs-decrypt-output" hidden></div>
    </div>
    `;
}

// ============================================================
// DECRYPTION HANDLERS
// ============================================================
async function cs_doOmniGuptDecrypt(resultId, rawValue) {
    const keyEl = document.getElementById('cs-dec-key-gcm');
    if (!keyEl) return;
    const key = keyEl.value.trim();
    if (!key) { showNotification('Passphrase or key is required.', 'warning'); return; }

    const outputEl = document.getElementById(`cs-decrypt-result-${resultId}`);
    if (outputEl) { outputEl.hidden = false; outputEl.innerHTML = '<span class="cs-muted">Decrypting…</span>'; }

    try {
        const isRaw = /^[0-9a-fA-F]{64}$/.test(key.replace(/\s/g, ''));
        const result = await window.decryptGCM(rawValue, key, isRaw);
        if (outputEl) {
            outputEl.innerHTML = `
                <div class="cs-decrypt-success">
                    <div class="cs-decode-step-label">✓ Decryption Successful</div>
                    <textarea class="cyber-textarea cs-decrypt-textarea" readonly>${cs_escapeHtml(result)}</textarea>
                    <button class="cyber-btn cyber-btn--green" onclick="cs_copyText(${JSON.stringify(result)})">📋 Copy Result</button>
                </div>
            `;
        }
        showNotification('Decryption successful!', 'success');
    } catch(e) {
        if (outputEl) {
            outputEl.innerHTML = `<div class="cs-info-alert cs-info-alert--error">✗ ${cs_escapeHtml(e.message)}</div>`;
        }
        showNotification('Decryption failed. Check key and format.', 'error');
    }
}

async function cs_doCryptoJSDecrypt(resultId) {
    const passEl = document.getElementById('cs-dec-pass-cjs');
    const algoEl = document.getElementById('cs-dec-algo-cjs');
    const outputEl = document.getElementById(`cs-decrypt-result-${resultId}`);

    if (!passEl || !algoEl) return;
    const pass = passEl.value;
    const algo = algoEl.value;
    const rawValue = _csCurrentFeatures ? _csCurrentFeatures.raw : '';

    if (!pass) { showNotification('Passphrase is required.', 'warning'); return; }
    if (outputEl) { outputEl.hidden = false; outputEl.innerHTML = '<span class="cs-muted">Decrypting…</span>'; }

    try {
        const result = await window.cryptoDecrypt(algo, rawValue, pass, false, null);
        if (outputEl) {
            outputEl.innerHTML = `
                <div class="cs-decrypt-success">
                    <div class="cs-decode-step-label">✓ Decryption Successful</div>
                    <textarea class="cyber-textarea cs-decrypt-textarea" readonly>${cs_escapeHtml(result)}</textarea>
                    <button class="cyber-btn cyber-btn--green" onclick="cs_copyText(${JSON.stringify(result)})">📋 Copy Result</button>
                </div>
            `;
        }
        showNotification('Decryption successful!', 'success');
    } catch(e) {
        if (outputEl) {
            outputEl.innerHTML = `<div class="cs-info-alert cs-info-alert--error">✗ Decryption failed. The selected algorithm, key, or format may be incorrect.</div>`;
        }
        showNotification('Decryption failed.', 'error');
    }
}

async function cs_doAESCBCDecrypt(resultId, rawValue) {
    const keyEl = document.getElementById('cs-dec-key-aes');
    const ivEl = document.getElementById('cs-dec-iv-aes');
    const outputEl = document.getElementById(`cs-decrypt-result-${resultId}`);

    if (!keyEl) return;
    const key = keyEl.value.trim();
    const iv = ivEl ? ivEl.value.trim() : '';
    if (!key) { showNotification('Hex key is required.', 'warning'); return; }
    if (outputEl) { outputEl.hidden = false; outputEl.innerHTML = '<span class="cs-muted">Decrypting…</span>'; }

    try {
        const result = await window.cryptoDecrypt('AES', rawValue, key, true, iv);
        if (outputEl) {
            outputEl.innerHTML = `
                <div class="cs-decrypt-success">
                    <div class="cs-decode-step-label">✓ Decryption Successful</div>
                    <textarea class="cyber-textarea cs-decrypt-textarea" readonly>${cs_escapeHtml(result)}</textarea>
                    <button class="cyber-btn cyber-btn--green" onclick="cs_copyText(${JSON.stringify(result)})">📋 Copy Result</button>
                </div>
            `;
        }
        showNotification('Decryption successful!', 'success');
    } catch(e) {
        if (outputEl) {
            outputEl.innerHTML = `<div class="cs-info-alert cs-info-alert--error">✗ Decryption failed. The selected algorithm, key, IV, or format may be incorrect.</div>`;
        }
        showNotification('Decryption failed.', 'error');
    }
}

// ============================================================
// HELPERS
// ============================================================
function cs_escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function cs_copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text)
            .then(() => showNotification('Copied to clipboard!', 'success'))
            .catch(() => showNotification('Failed to copy.', 'error'));
    } else {
        showNotification('Clipboard unavailable in this context.', 'warning');
    }
}

function cs_toggleDecInput(id) {
    const el = document.getElementById(id);
    if (el) el.type = el.type === 'password' ? 'text' : 'password';
}

function cs_showConfidenceInfo() {
    showNotification('Confidence = heuristic match strength, not a mathematical probability of exact algorithm.', 'info');
}

function cs_showAllResults() {
    _csShowingAll = true;
    cs_renderResults(_csCurrentResults, true);
}

// ============================================================
// MAIN ANALYZE TRIGGER
// ============================================================
function cs_triggerAnalysis() {
    const inputEl = document.getElementById('cs-input');
    if (!inputEl) return;
    const raw = inputEl.value;

    if (!raw.trim()) {
        showNotification('Input is empty.', 'warning');
        return;
    }

    // Show loading state
    const summaryEl = document.getElementById('cs-summary');
    const resultsEl = document.getElementById('cs-results');
    if (summaryEl) summaryEl.innerHTML = '<div class="cs-loading"><div class="cs-spinner"></div><span>Analyzing…</span></div>';
    if (resultsEl) resultsEl.innerHTML = '';

    // Analysis is synchronous but show briefly
    setTimeout(() => {
        const analysis = window.cipherSense.analyze(raw);

        if (analysis.error) {
            showNotification(analysis.error, 'warning');
            if (summaryEl) summaryEl.innerHTML = '';
            return;
        }

        _csCurrentFeatures = analysis.features;
        _csCurrentResults = analysis.results;
        _csShowingAll = false;

        // Show section
        const analysisSection = document.getElementById('cs-analysis-section');
        if (analysisSection) analysisSection.hidden = false;

        cs_renderSummary(analysis.features);
        cs_renderResults(analysis.results, false);
    }, 50);
}

// ============================================================
// CLEAR
// ============================================================
function cs_clearAll() {
    const inputEl = document.getElementById('cs-input');
    if (inputEl) inputEl.value = '';

    _csCurrentResults = [];
    _csCurrentFeatures = null;
    _csShowingAll = false;

    const summaryEl = document.getElementById('cs-summary');
    const resultsEl = document.getElementById('cs-results');
    if (summaryEl) summaryEl.innerHTML = '';
    if (resultsEl) resultsEl.innerHTML = '';

    const analysisSection = document.getElementById('cs-analysis-section');
    if (analysisSection) analysisSection.hidden = true;
}

// ============================================================
// PASTE FROM CLIPBOARD (explicit user action only)
// ============================================================
async function cs_pasteFromClipboard() {
    if (!navigator.clipboard || !window.isSecureContext) {
        showNotification('Clipboard access unavailable. Please paste manually.', 'warning');
        return;
    }
    try {
        const text = await navigator.clipboard.readText();
        const inputEl = document.getElementById('cs-input');
        if (inputEl) {
            inputEl.value = text;
            showNotification('Pasted from clipboard.', 'success');
        }
    } catch(e) {
        showNotification('Clipboard read permission denied. Please paste manually.', 'warning');
    }
}

// ============================================================
// GLOBAL EXPORTS
// ============================================================
window.cs_triggerAnalysis = cs_triggerAnalysis;
window.cs_clearAll = cs_clearAll;
window.cs_pasteFromClipboard = cs_pasteFromClipboard;
window.cs_toggleEvidence = cs_toggleEvidence;
window.cs_handleAction = cs_handleAction;
window.cs_showAllResults = cs_showAllResults;
window.cs_copyText = cs_copyText;
window.cs_toggleDecInput = cs_toggleDecInput;
window.cs_showConfidenceInfo = cs_showConfidenceInfo;
window.cs_doOmniGuptDecrypt = cs_doOmniGuptDecrypt;
window.cs_doCryptoJSDecrypt = cs_doCryptoJSDecrypt;
window.cs_doAESCBCDecrypt = cs_doAESCBCDecrypt;

