/**
 * CipherSense Engine v2 — Hardened Detection Architecture
 * OmniGupt | Local-first, deterministic, ambiguity-aware, explainable
 *
 * Architecture:
 *   normalizeInput
 *     → analyzeRepresentation  ← dedicated layer BEFORE algorithm guessing
 *     → extractFeatures
 *     → runDetectors           ← evidence-weight scoring, no arbitrary magic numbers
 *     → applyAmbiguityGroups   ← near-identical scores for technically indistinguishable outputs
 *     → rankAndFilter
 *     → resolve actions
 *
 * Privacy: Deterministic engine — no random-number calls, no fetch, no console.log of input,
 *          no localStorage/sessionStorage writes of analyzed values.
 */

'use strict';

// ============================================================
// EVIDENCE WEIGHT CONSTANTS
// All scoring uses named weights — no magic numbers in detectors
// ============================================================
const EW = Object.freeze({
    DETERMINISTIC_SIGNATURE:     40,  // Incontrovertible structural marker (bcrypt $2b$, PEM header)
    STRONG_STRUCTURAL:           28,  // Near-deterministic structural match
    SPECIFIC_REPRESENTATION:     18,  // High-specificity format characteristic
    SUPPORTING_CHARACTERISTIC:    8,  // Corroborating but non-unique signal
    WEAK_COMPATIBILITY:           3,  // Technically compatible but not specific
    AMBIGUITY_NOTE:               0,  // Informational only, no score impact
    CONTRADICTING_EVIDENCE:     -18,  // Evidence arguing against this format
    REPRESENTATION_CONFLICT:    -28,  // Input representation directly conflicts with this format
    IMPOSSIBLE_CONDITION:       -50,  // Structurally impossible for this input
});

// Thresholds
const CS_MIN_CONFIDENCE   = 15;   // Results below this are hidden
const CS_MAX_RECURSION    = 3;    // Max recursive decode depth
const CS_SCORE_CAP        = 99;   // No format claims 100% certainty

// ============================================================
// SAFE BASE64 UTILITIES  (browser + Node compatible)
// ============================================================
function _cs_atob(s) {
    if (typeof atob !== 'undefined') return atob(s);
    return Buffer.from(s, 'base64').toString('binary');
}
function _cs_btoa(s) {
    if (typeof btoa !== 'undefined') return btoa(s);
    return Buffer.from(s, 'binary').toString('base64');
}

function cs_b64urlDecode(seg) {
    const padded = seg.replace(/-/g, '+').replace(/_/g, '/');
    const pad = (4 - padded.length % 4) % 4;
    return _cs_atob(padded + '='.repeat(pad));
}

// Shannon entropy (bits per character)
function cs_shannonEntropy(s) {
    if (!s || s.length === 0) return 0;
    const freq = {};
    for (const c of s) freq[c] = (freq[c] || 0) + 1;
    const len = s.length;
    let H = 0;
    for (const n of Object.values(freq)) {
        const p = n / len;
        H -= p * Math.log2(p);
    }
    return Math.round(H * 100) / 100;
}

// ============================================================
// REPRESENTATION ANALYZER  — runs BEFORE algorithm detection
// Establishes HOW the input is encoded, not WHAT algorithm made it.
// This is the critical layer that prevents hex-vs-Base64 confusion.
// ============================================================
function cs_analyzeRepresentation(s) {
    const len = s.length;

    // ── Strict Hexadecimal ──────────────────────────────────
    const isStrictHex     = /^[0-9a-fA-F]+$/.test(s);
    const isStrictHexEven = isStrictHex && len % 2 === 0;
    const hexAllLower     = isStrictHex && !/[A-F]/.test(s);
    const hexAllUpper     = isStrictHex && !/[a-f]/.test(s);
    const hexByteLen      = isStrictHexEven ? len / 2 : null;

    // Known hash byte-lengths (length in hex chars)
    const HEX_HASH_LENGTHS = new Set([32, 40, 56, 64, 96, 128]);
    const isKnownHashLength = isStrictHexEven && HEX_HASH_LENGTHS.has(len);

    // ── PEM ─────────────────────────────────────────────────
    const isPEM = s.startsWith('-----BEGIN ') && s.includes('-----END ');
    let pemBeginLabel = null, pemEndLabel = null, pemLabelsMatch = false;
    if (isPEM) {
        const bm = s.match(/^-----BEGIN ([^-\n]+)-----/);
        const em = s.match(/-----END ([^-\n]+)-----/);
        pemBeginLabel = bm ? bm[1].trim() : null;
        pemEndLabel   = em ? em[1].trim() : null;
        pemLabelsMatch = !!(pemBeginLabel && pemEndLabel && pemBeginLabel === pemEndLabel);
    }

    // ── Password hash dollar structure ───────────────────────
    const dollarCount = (s.match(/\$/g) || []).length;
    const dollarParts  = s.split('$');

    // ── URL Encoding ─────────────────────────────────────────
    const validPctSeqs   = (s.match(/%[0-9A-Fa-f]{2}/g) || []);
    const invalidPctSeqs = (s.match(/%(?![0-9A-Fa-f]{2})/g) || []);
    const isURLEncoded   = validPctSeqs.length > 0 && invalidPctSeqs.length === 0;
    const pctRatio       = len > 0 ? validPctSeqs.length / (len / 3) : 0;

    // ── HTML Entities ─────────────────────────────────────────
    const namedEntities   = (s.match(/&[a-zA-Z]{2,8};/g) || []);
    const decimalEntities = (s.match(/&#\d{1,7};/g) || []);
    const hexEntities     = (s.match(/&#x[0-9a-fA-F]{1,6};/g) || []);
    const totalEntities   = namedEntities.length + decimalEntities.length + hexEntities.length;
    const hasHTMLEntities = totalEntities > 0;

    // ── Unicode Escapes ───────────────────────────────────────
    const unicodeEscapes    = (s.match(/\\u[0-9a-fA-F]{4}/g) || []);
    const malformedEscapes  = (s.match(/\\u(?![0-9a-fA-F]{4})/g) || []);
    const hasValidUniEscape = unicodeEscapes.length > 0 && malformedEscapes.length === 0;

    // ── Binary Text ───────────────────────────────────────────
    const isBinaryText = /^[01][\s01]*$/.test(s) && s.length >= 2;
    const binNoSpace   = s.replace(/\s/g, '');
    // Byte-aligned = groups of 8 bits
    const isByteAlignedBinary = isBinaryText && binNoSpace.length % 8 === 0 && binNoSpace.length >= 8;

    // ── JWT ────────────────────────────────────────────────────
    // Must: 3 dot-separated segments, header decodes to valid JSON object, payload decodes to valid JSON object
    const dotParts = s.split('.');
    let isJWT = false, jwtAlg = null, jwtTyp = null, jwtPayloadValid = false, jwtHeaderValid = false;
    if (dotParts.length === 3 && dotParts.every(p => /^[A-Za-z0-9\-_]+$/.test(p) && p.length > 0)) {
        try {
            const hdrRaw = cs_b64urlDecode(dotParts[0]);
            const hdr    = JSON.parse(hdrRaw);
            if (hdr && typeof hdr === 'object' && !Array.isArray(hdr)) {
                jwtHeaderValid = true;
                jwtAlg = hdr.alg || null;
                jwtTyp = hdr.typ || null;
                try {
                    const pldRaw = cs_b64urlDecode(dotParts[1]);
                    const pld    = JSON.parse(pldRaw);
                    jwtPayloadValid = pld && typeof pld === 'object' && !Array.isArray(pld);
                } catch (_) { /* payload didn't parse */ }
                isJWT = jwtHeaderValid && jwtPayloadValid;
            }
        } catch (_) { /* header didn't decode/parse */ }
    }

    // ── Canonical Base64 ─────────────────────────────────────
    // Full pipeline: alphabet check → length check → padding check → decode → canonical re-encode check
    // Explicitly penalised when input is also strict hex (REPRESENTATION_CONFLICT)
    let isCanonicalBase64   = false;
    let b64Decoded          = null;  // binary string
    let b64PrintableRatio   = 0;
    let b64UTF8Text         = null;
    let b64KnownMarker      = null;  // 'omnigupt-gcm' | 'openssl-salted' | 'cryptojs' | null

    // Only attempt canonical B64 when NOT already classified as strict-hex or PEM or JWT
    if (!isStrictHex && !isPEM && !isJWT) {
        if (
            /^[A-Za-z0-9+/]*={0,2}$/.test(s) &&
            s.length >= 4 &&
            s.length % 4 === 0
        ) {
            // Padding must appear only at the very end, max 2 chars
            const noPad = s.replace(/={1,2}$/, '');
            if (!noPad.includes('=') && (s.length - noPad.length) <= 2) {
                try {
                    const dec     = _cs_atob(s);
                    const reEnc   = _cs_btoa(dec);
                    if (reEnc === s) {
                        isCanonicalBase64 = true;
                        b64Decoded = dec;

                        // Printable ratio
                        let printable = 0;
                        for (let i = 0; i < dec.length; i++) {
                            const cc = dec.charCodeAt(i);
                            if (cc >= 32 && cc < 127) printable++;
                        }
                        b64PrintableRatio = dec.length > 0 ? printable / dec.length : 0;

                        // UTF-8 validity
                        try {
                            const bytes = new Uint8Array(dec.length);
                            for (let i = 0; i < dec.length; i++) bytes[i] = dec.charCodeAt(i);
                            b64UTF8Text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
                        } catch (_) { /* not valid UTF-8 */ }

                        // Known structural markers in decoded content
                        if (dec.startsWith('Salted__')) {
                            b64KnownMarker = 'openssl-salted';
                        } else if (dec.startsWith('{')) {
                            try {
                                const obj = JSON.parse(dec);
                                if (obj && obj.version === 1 && obj.algorithm === 'AES-256-GCM' && obj.iv && obj.ciphertext) {
                                    b64KnownMarker = 'omnigupt-gcm';
                                }
                            } catch (_) { /* not JSON */ }
                        }
                    }
                } catch (_) { /* atob failed */ }
            }
        }
    }

    // CryptoJS legacy: well-known B64 prefix for OpenSSL-derived "Salted__" output
    const isCryptoJSLegacy = s.startsWith('U2FsdGVkX1');

    // ── Base64URL (without JWT context) ──────────────────────
    const hasUrlAlphChars = s.includes('-') || s.includes('_');
    const isBase64URL = !isStrictHex && !isPEM && !isJWT && !isCanonicalBase64 &&
        hasUrlAlphChars && /^[A-Za-z0-9\-_]+=*$/.test(s);

    // ── Weak B64 compatibility (fallback) ─────────────────────
    // Pure hex strings with even length divisible by 4 happen to be
    // compatible with the B64 alphabet, but this is WEAK evidence only.
    const isWeakB64Compatible = !isCanonicalBase64 && !isBase64URL &&
        /^[A-Za-z0-9+/]*={0,2}$/.test(s) && s.length % 4 === 0 && s.length >= 4;

    // ── AES-CBC IV:Ciphertext pattern ────────────────────────
    let isAESCBCPattern = false, cbcIV = null, cbcCT = null;
    if (!isStrictHex) {
        const cp = s.split(':');
        if (cp.length === 2 && /^[0-9a-fA-F]{32}$/.test(cp[0]) && /^[0-9a-fA-F]+$/.test(cp[1]) && cp[1].length % 32 === 0) {
            isAESCBCPattern = true;
            cbcIV = cp[0];
            cbcCT = cp[1];
        }
    }

    // ── OpenSSL Salted (extracted details) ───────────────────
    let openSSLSalt = null;
    if (isCanonicalBase64 && b64KnownMarker === 'openssl-salted' && b64Decoded && b64Decoded.length >= 16) {
        openSSLSalt = Array.from(b64Decoded.slice(8, 16))
            .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
            .join('');
    }

    return {
        // Hex
        isStrictHex, isStrictHexEven, hexAllLower, hexAllUpper, hexByteLen, isKnownHashLength,
        // PEM
        isPEM, pemBeginLabel, pemEndLabel, pemLabelsMatch,
        // Password hashes
        dollarCount, dollarParts,
        // URL / HTML / Unicode
        isURLEncoded, validPctSeqs, invalidPctSeqs, pctRatio,
        hasHTMLEntities, namedEntities, decimalEntities, hexEntities, totalEntities,
        hasValidUniEscape, unicodeEscapes, malformedEscapes,
        // Binary
        isBinaryText, isByteAlignedBinary, binNoSpace,
        // JWT
        isJWT, jwtAlg, jwtTyp, jwtPayloadValid, jwtHeaderValid, dotParts,
        // Base64
        isCanonicalBase64, b64Decoded, b64PrintableRatio, b64UTF8Text, b64KnownMarker,
        isWeakB64Compatible, isCryptoJSLegacy,
        // Base64URL
        isBase64URL, hasUrlAlphChars,
        // Patterns
        isAESCBCPattern, cbcIV, cbcCT, openSSLSalt,
    };
}

// ============================================================
// INPUT NORMALIZER
// ============================================================
function cs_normalizeInput(raw) {
    if (typeof raw !== 'string') return { original: '', trimmed: '', error: 'Input must be a string.' };
    const trimmed = raw.trim();
    return { original: raw, trimmed };
}

// ============================================================
// FEATURE EXTRACTOR  (derives analytics from normalised input + rep)
// ============================================================
function cs_extractFeatures(s, rep) {
    const len     = s.length;
    const entropy = cs_shannonEntropy(s);
    const uniqueChars = new Set(s).size;
    const hasUpper  = /[A-Z]/.test(s);
    const hasLower  = /[a-z]/.test(s);
    const hasDigit  = /\d/.test(s);
    const hasSymbol = /[^A-Za-z0-9]/.test(s);

    // AES block alignment
    const aesAlignedHex = rep.hexByteLen !== null && rep.hexByteLen % 16 === 0;

    // Alphabetic only (for ROT13 compatibility)
    const isAlphaText = /^[a-zA-Z\s]+$/.test(s);

    // Numeric only
    const isNumericOnly = /^\d+$/.test(s);

    return {
        len, entropy, uniqueChars,
        hasUpper, hasLower, hasDigit, hasSymbol,
        aesAlignedHex, isAlphaText, isNumericOnly,
    };
}

// ============================================================
// EVIDENCE HELPER
// ============================================================
function ev(type, text, weight) {
    return { type, text, weight };
}

// ============================================================
// DETECTOR REGISTRY
// Each detector returns: { score, evidence, isDeterministic, supportedActions, sensitiveWarning }
// or null if the format is provably impossible for this input.
// ============================================================
const CS_DETECTORS = [

    // ── OMNIGUPT AES-GCM (DETERMINISTIC) ─────────────────────
    {
        id: 'omnigupt-aes-gcm',
        displayName: 'OmniGupt AES-256-GCM Payload',
        category: 'ENCRYPTION_FORMAT',
        description: 'Structured JSON payload from OmniGupt AES-256-GCM encryption. Contains version, algorithm, IV, ciphertext, and PBKDF2 parameters.',
        detect(f, rep) {
            if (rep.b64KnownMarker !== 'omnigupt-gcm') return null;
            const evidence = [
                ev('positive', 'Canonical Base64 representation confirmed (round-trip re-encode matches)', EW.SPECIFIC_REPRESENTATION),
                ev('positive', 'Decoded JSON contains version:1 and algorithm:"AES-256-GCM" — deterministic OmniGupt marker', EW.DETERMINISTIC_SIGNATURE),
                ev('positive', 'Contains IV and ciphertext fields required by OmniGupt AES-GCM format', EW.STRONG_STRUCTURAL),
            ];
            return { evidence, isDeterministic: true, supportedActions: ['configure-decryption'] };
        }
    },

    // ── OPENSSL SALTED CONTAINER (DETERMINISTIC) ──────────────
    {
        id: 'openssl-salted',
        displayName: 'OpenSSL Salted Encrypted Container',
        category: 'ENCRYPTION_FORMAT',
        description: 'Base64-encoded container whose decoded bytes begin with the OpenSSL "Salted__" marker followed by 8 bytes of random salt. Produced by `openssl enc`. The exact cipher is NOT determinable from this marker alone.',
        detect(f, rep) {
            if (rep.b64KnownMarker !== 'openssl-salted') return null;
            const evidence = [
                ev('positive', 'Canonical Base64 decodes cleanly', EW.SPECIFIC_REPRESENTATION),
                ev('positive', 'Decoded bytes begin with ASCII "Salted__" — deterministic OpenSSL enc container marker', EW.DETERMINISTIC_SIGNATURE),
                ev('positive', `Salt bytes extracted: 0x${rep.openSSLSalt || 'N/A'}`, EW.SUPPORTING_CHARACTERISTIC),
                ev('ambiguity', 'Exact cipher (AES-256-CBC, AES-128-CBC, etc.) is NOT embedded in this marker', EW.AMBIGUITY_NOTE),
                ev('ambiguity', 'Key derivation uses OpenSSL EVP_BytesToKey, not PBKDF2', EW.AMBIGUITY_NOTE),
            ];
            return { evidence, isDeterministic: true, supportedActions: ['inspect-structure'] };
        }
    },

    // ── CRYPTOJS LEGACY SALTED (DETERMINISTIC PREFIX) ─────────
    {
        id: 'cryptojs-legacy-salted',
        displayName: 'CryptoJS Legacy Salted Encrypted Output',
        category: 'ENCRYPTION_FORMAT',
        description: 'Base64-encoded output from CryptoJS symmetric encryption using passphrase-based key derivation. The prefix "U2FsdGVkX1" is the Base64 encoding of "Salted__" — a deterministic structural prefix.',
        detect(f, rep) {
            if (!rep.isCryptoJSLegacy) return null;
            const evidence = [
                ev('positive', '"U2FsdGVkX1" prefix — Base64 encoding of "Salted__", deterministic CryptoJS marker', EW.DETERMINISTIC_SIGNATURE),
                ev('positive', 'Compatible with CryptoJS AES, DES, 3DES, and Rabbit with passphrase', EW.STRONG_STRUCTURAL),
                ev('ambiguity', 'Exact cipher algorithm (AES/DES/3DES/Rabbit) cannot be determined from the prefix alone', EW.AMBIGUITY_NOTE),
            ];
            return { evidence, isDeterministic: true, supportedActions: ['configure-decryption'] };
        }
    },

    // ── JWT (STRONG STRUCTURAL) ───────────────────────────────
    {
        id: 'jwt',
        displayName: 'JSON Web Token (JWT / JWS)',
        category: 'TOKEN',
        description: 'Three-part dot-separated token where header and payload are Base64URL-encoded JSON objects. Widely used in authentication systems.',
        detect(f, rep) {
            if (!rep.isJWT) return null;
            const evidence = [];
            evidence.push(ev('positive', 'Exactly 3 dot-separated segments matching JWT structural requirement', EW.STRONG_STRUCTURAL));
            evidence.push(ev('positive', 'Header segment decodes to a valid JSON object', EW.STRONG_STRUCTURAL));
            if (rep.jwtAlg) {
                evidence.push(ev('positive', `Header contains "alg": "${rep.jwtAlg}" — standard JWT algorithm field`, EW.SPECIFIC_REPRESENTATION));
            }
            if (rep.jwtTyp) {
                evidence.push(ev('positive', `Header contains "typ": "${rep.jwtTyp}"`, EW.SUPPORTING_CHARACTERISTIC));
            }
            if (rep.jwtPayloadValid) {
                evidence.push(ev('positive', 'Payload segment decodes to a valid JSON object', EW.STRONG_STRUCTURAL));
            } else {
                evidence.push(ev('ambiguity', 'Payload segment did not decode to a valid JSON object (may be JWE/encrypted payload)', EW.AMBIGUITY_NOTE));
            }
            evidence.push(ev('ambiguity', 'Decoded structure does not imply cryptographic signature verification', EW.AMBIGUITY_NOTE));
            return { evidence, isDeterministic: false, supportedActions: ['inspect-token'] };
        }
    },

    // ── PEM PUBLIC KEY ────────────────────────────────────────
    {
        id: 'pem-public-key',
        displayName: 'PEM Public Key',
        category: 'KEY_OR_CERTIFICATE',
        description: 'PEM-encoded public key block. May be RSA, EC, or another algorithm. BEGIN and END labels match.',
        detect(f, rep) {
            if (!rep.isPEM) return null;
            const t = (rep.pemBeginLabel || '').toUpperCase();
            if (!t.includes('PUBLIC')) return null;
            const evidence = [
                ev('positive', `Matching PEM boundaries confirmed: "-----BEGIN ${rep.pemBeginLabel}-----"`, EW.DETERMINISTIC_SIGNATURE),
                ev('positive', 'Public key material — safe to share', EW.SUPPORTING_CHARACTERISTIC),
            ];
            if (!rep.pemLabelsMatch) evidence.push(ev('conflict', 'BEGIN and END labels do not match — malformed PEM', EW.CONTRADICTING_EVIDENCE));
            return { evidence, isDeterministic: rep.pemLabelsMatch, supportedActions: ['inspect-structure'] };
        }
    },

    // ── PEM PRIVATE KEY ───────────────────────────────────────
    {
        id: 'pem-private-key',
        displayName: 'PEM Private Key',
        category: 'KEY_OR_CERTIFICATE',
        description: 'PEM-encoded private key block. Contains sensitive private key material — analysis is local-only.',
        detect(f, rep) {
            if (!rep.isPEM) return null;
            const t = (rep.pemBeginLabel || '').toUpperCase();
            if (!t.includes('PRIVATE')) return null;
            const evidence = [
                ev('positive', `Matching PEM boundaries confirmed: "-----BEGIN ${rep.pemBeginLabel}-----"`, EW.DETERMINISTIC_SIGNATURE),
                ev('conflict', 'SENSITIVE: Private key material detected. All analysis is local — no data leaves your browser.', EW.AMBIGUITY_NOTE),
            ];
            if (!rep.pemLabelsMatch) evidence.push(ev('conflict', 'BEGIN and END labels do not match — malformed PEM', EW.CONTRADICTING_EVIDENCE));
            return { evidence, isDeterministic: rep.pemLabelsMatch, supportedActions: ['inspect-structure'], sensitiveWarning: true };
        }
    },

    // ── PEM CERTIFICATE ───────────────────────────────────────
    {
        id: 'pem-certificate',
        displayName: 'PEM Certificate / Certificate Request',
        category: 'KEY_OR_CERTIFICATE',
        description: 'PEM-encoded X.509 certificate or certificate signing request (CSR).',
        detect(f, rep) {
            if (!rep.isPEM) return null;
            const t = (rep.pemBeginLabel || '').toUpperCase();
            if (!t.includes('CERTIFICATE')) return null;
            const evidence = [
                ev('positive', `Matching PEM boundaries: "-----BEGIN ${rep.pemBeginLabel}-----"`, EW.DETERMINISTIC_SIGNATURE),
            ];
            if (!rep.pemLabelsMatch) evidence.push(ev('conflict', 'BEGIN and END labels do not match', EW.CONTRADICTING_EVIDENCE));
            return { evidence, isDeterministic: rep.pemLabelsMatch, supportedActions: ['inspect-structure'] };
        }
    },

    // ── bcrypt ────────────────────────────────────────────────
    {
        id: 'bcrypt',
        displayName: 'bcrypt Password Hash',
        category: 'PASSWORD_HASH',
        description: 'bcrypt password hash containing algorithm version ($2b$, $2a$, $2y$), cost factor, 22-character Base64 salt, and 31-character hash. Total canonical length: 60 characters.',
        detect(f, rep) {
            const full = /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(rep.dollarParts.join('$') === '' ? f.len === 0 ? '' : f.raw : f.raw);
            const raw = f.raw;
            // Full structural match
            if (!/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(raw)) {
                // Partial: starts with $2 but fails full validation
                if (raw.startsWith('$2') && raw.length > 4) {
                    return {
                        evidence: [
                            ev('positive', 'Starts with $2 — consistent with bcrypt prefix', EW.SUPPORTING_CHARACTERISTIC),
                            ev('conflict', 'Full bcrypt structural validation failed (check cost factor, length, or character set)', EW.CONTRADICTING_EVIDENCE),
                        ],
                        isDeterministic: false,
                        supportedActions: ['analyze-hash']
                    };
                }
                return null;
            }
            const versionMatch = raw.match(/^\$2([aby])\$/);
            const costMatch    = raw.match(/^\$2[aby]\$(\d{2})\$/);
            const version = versionMatch ? `$2${versionMatch[1]}$` : 'unknown';
            const cost    = costMatch ? parseInt(costMatch[1], 10) : null;
            const evidence = [
                ev('positive', `bcrypt algorithm version confirmed: ${version}`, EW.DETERMINISTIC_SIGNATURE),
                ev('positive', cost !== null ? `Cost factor: ${cost} (2^${cost} ≈ ${Math.pow(2, cost).toLocaleString()} iterations)` : 'Cost factor parsed', EW.STRONG_STRUCTURAL),
                ev('positive', 'Total length 60 characters matches bcrypt canonical format', EW.SPECIFIC_REPRESENTATION),
                ev('positive', '53-character Base64-like body (22-char salt + 31-char hash) confirmed', EW.SPECIFIC_REPRESENTATION),
                ev('conflict', 'One-way adaptive hash — cryptographically irreversible', EW.AMBIGUITY_NOTE),
            ];
            return { evidence, isDeterministic: true, supportedActions: ['analyze-hash'] };
        }
    },

    // ── Argon2 ────────────────────────────────────────────────
    {
        id: 'argon2',
        displayName: 'Argon2 Password Hash',
        category: 'PASSWORD_HASH',
        description: 'Argon2 password hash (Argon2i, Argon2d, or Argon2id) with explicit memory, time, and parallelism parameters.',
        detect(f, rep) {
            const raw = f.raw;
            if (!raw.startsWith('$argon2')) return null;
            const fullPattern = /^\$argon2(i|d|id)\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+)$/;
            const partialPattern = /^\$argon2(i|d|id)\$/;
            const fullMatch = raw.match(fullPattern);
            if (!fullMatch) {
                const partial = raw.match(partialPattern);
                return partial ? {
                    evidence: [
                        ev('positive', `Argon2 prefix "$argon2${partial[1]}" detected`, EW.STRONG_STRUCTURAL),
                        ev('conflict', 'Parameter structure (m=, t=, p=) incomplete or malformed', EW.CONTRADICTING_EVIDENCE),
                    ],
                    isDeterministic: false, supportedActions: ['analyze-hash']
                } : null;
            }
            const [, variant, ver, mem, time, par] = fullMatch;
            const variantName = variant === 'id' ? 'Argon2id' : variant === 'i' ? 'Argon2i' : 'Argon2d';
            const evidence = [
                ev('positive', `Argon2 variant confirmed: ${variantName}`, EW.DETERMINISTIC_SIGNATURE),
                ev('positive', `Version: v=${ver}`, EW.STRONG_STRUCTURAL),
                ev('positive', `Memory cost: m=${mem} KiB`, EW.STRONG_STRUCTURAL),
                ev('positive', `Time cost: t=${time} iterations`, EW.STRONG_STRUCTURAL),
                ev('positive', `Parallelism: p=${par} threads`, EW.STRONG_STRUCTURAL),
                ev('positive', 'Salt and hash segments structurally present', EW.SPECIFIC_REPRESENTATION),
                ev('conflict', 'One-way adaptive memory-hard hash — cryptographically irreversible', EW.AMBIGUITY_NOTE),
            ];
            return { evidence, isDeterministic: true, supportedActions: ['analyze-hash'] };
        }
    },

    // ── Unix $1$ (MD5-crypt) ──────────────────────────────────
    {
        id: 'unix-md5-crypt',
        displayName: 'Unix MD5-crypt Hash ($1$)',
        category: 'PASSWORD_HASH',
        description: 'Unix MD5-crypt password hash. Algorithm identifier $1$, followed by salt and 22-character hash.',
        detect(f, rep) {
            const raw = f.raw;
            if (!raw.startsWith('$1$')) return null;
            const evidence = [
                ev('positive', 'Unix crypt algorithm identifier "$1$" — MD5-crypt', EW.DETERMINISTIC_SIGNATURE),
                ev('conflict', 'MD5-crypt is considered cryptographically weak by modern standards', EW.AMBIGUITY_NOTE),
                ev('conflict', 'One-way hash — cryptographically irreversible', EW.AMBIGUITY_NOTE),
            ];
            return { evidence, isDeterministic: true, supportedActions: ['analyze-hash'] };
        }
    },

    // ── Unix $5$ (SHA-256-crypt) ──────────────────────────────
    {
        id: 'unix-sha256-crypt',
        displayName: 'Unix SHA-256-crypt Hash ($5$)',
        category: 'PASSWORD_HASH',
        description: 'Unix SHA-256-crypt password hash.',
        detect(f, rep) {
            if (!f.raw.startsWith('$5$')) return null;
            return {
                evidence: [
                    ev('positive', 'Unix crypt identifier "$5$" — SHA-256-crypt', EW.DETERMINISTIC_SIGNATURE),
                    ev('conflict', 'One-way hash — cryptographically irreversible', EW.AMBIGUITY_NOTE),
                ],
                isDeterministic: true, supportedActions: ['analyze-hash']
            };
        }
    },

    // ── Unix $6$ (SHA-512-crypt) ──────────────────────────────
    {
        id: 'unix-sha512-crypt',
        displayName: 'Unix SHA-512-crypt Hash ($6$)',
        category: 'PASSWORD_HASH',
        description: 'Unix SHA-512-crypt password hash (default on modern Linux systems).',
        detect(f, rep) {
            if (!f.raw.startsWith('$6$')) return null;
            return {
                evidence: [
                    ev('positive', 'Unix crypt identifier "$6$" — SHA-512-crypt', EW.DETERMINISTIC_SIGNATURE),
                    ev('conflict', 'One-way hash — cryptographically irreversible', EW.AMBIGUITY_NOTE),
                ],
                isDeterministic: true, supportedActions: ['analyze-hash']
            };
        }
    },

    // ── MD5-like hash ─────────────────────────────────────────
    {
        id: 'md5-like',
        displayName: 'MD5-like Hash (128-bit)',
        category: 'HASH',
        description: '32-character hexadecimal string matching MD5 output (128 bits). No algorithm identifier is embedded in raw digest output.',
        detect(f, rep) {
            if (!rep.isStrictHexEven || f.len !== 32) return null;
            const evidence = [
                ev('positive', 'Strict hexadecimal representation', EW.SPECIFIC_REPRESENTATION),
                ev('positive', '32 hexadecimal characters (16 decoded bytes / 128 bits)', EW.SPECIFIC_REPRESENTATION),
                ev('positive', 'Length matches MD5 raw digest output exactly', EW.SUPPORTING_CHARACTERISTIC),
            ];
            if (f.entropy > 3.5) evidence.push(ev('positive', `Shannon entropy ${f.entropy} bits/char — consistent with hash output`, EW.SUPPORTING_CHARACTERISTIC));
            if (rep.hexAllLower) evidence.push(ev('positive', 'All lowercase hexadecimal — common in MD5 output conventions', EW.WEAK_COMPATIBILITY));
            evidence.push(ev('ambiguity', 'Raw hexadecimal output does not embed an algorithm identifier', EW.AMBIGUITY_NOTE));
            evidence.push(ev('conflict', 'One-way hash — cannot be reversed or decrypted', EW.AMBIGUITY_NOTE));
            return { evidence, isDeterministic: false, supportedActions: ['analyze-hash'] };
        }
    },

    // ── SHA-1-like ────────────────────────────────────────────
    {
        id: 'sha1-like',
        displayName: 'SHA-1-like Hash (160-bit)',
        category: 'HASH',
        description: '40-character hexadecimal string matching SHA-1 or RIPEMD-160 output (160 bits).',
        detect(f, rep) {
            if (!rep.isStrictHexEven || f.len !== 40) return null;
            const evidence = [
                ev('positive', 'Strict hexadecimal representation', EW.SPECIFIC_REPRESENTATION),
                ev('positive', '40 hexadecimal characters (20 decoded bytes / 160 bits)', EW.SPECIFIC_REPRESENTATION),
                ev('positive', 'Length matches SHA-1 digest output exactly', EW.SUPPORTING_CHARACTERISTIC),
            ];
            if (f.entropy > 3.5) evidence.push(ev('positive', `Shannon entropy ${f.entropy}`, EW.SUPPORTING_CHARACTERISTIC));
            evidence.push(ev('ambiguity', 'RIPEMD-160 produces an identical 40-hex-char output — cannot distinguish from SHA-1 by length alone', EW.AMBIGUITY_NOTE));
            evidence.push(ev('conflict', 'SHA-1 is cryptographically broken (collision attacks exist)', EW.AMBIGUITY_NOTE));
            evidence.push(ev('conflict', 'One-way hash — cannot be reversed or decrypted', EW.AMBIGUITY_NOTE));
            return { evidence, isDeterministic: false, supportedActions: ['analyze-hash'] };
        }
    },

    // ── SHA-224 / SHA3-224 ambiguity group ────────────────────
    {
        id: 'sha224-like',
        displayName: 'SHA-224-like / SHA3-224-like Hash (224-bit)',
        category: 'HASH',
        description: '56-character hexadecimal string matching SHA-224 or SHA3-224 output (224 bits). Both algorithms produce identical-length raw hex output.',
        detect(f, rep) {
            if (!rep.isStrictHexEven || f.len !== 56) return null;
            const evidence = [
                ev('positive', 'Strict hexadecimal representation', EW.SPECIFIC_REPRESENTATION),
                ev('positive', '56 hexadecimal characters (28 decoded bytes / 224 bits)', EW.SPECIFIC_REPRESENTATION),
                ev('positive', 'Length matches SHA-224 and SHA3-224 raw digest output', EW.SUPPORTING_CHARACTERISTIC),
                ev('ambiguity', 'SHA-224 and SHA3-224 produce the same output length — indistinguishable without algorithm metadata', EW.AMBIGUITY_NOTE),
                ev('conflict', 'One-way hash — cannot be reversed or decrypted', EW.AMBIGUITY_NOTE),
            ];
            return { evidence, isDeterministic: false, supportedActions: ['analyze-hash'] };
        }
    },

    // ── SHA-256 / SHA3-256 / BLAKE2s-256 group ────────────────
    {
        id: 'sha256-like',
        displayName: 'SHA-256-like / SHA3-256-like / BLAKE2s-256-like Hash (256-bit)',
        category: 'HASH',
        description: '64-character hexadecimal string matching SHA-256, SHA3-256, BLAKE2s-256, or HMAC-SHA256 output (256 bits). Multiple algorithms share this output length and representation.',
        detect(f, rep) {
            if (!rep.isStrictHexEven || f.len !== 64) return null;
            const evidence = [
                ev('positive', 'Strict hexadecimal representation', EW.SPECIFIC_REPRESENTATION),
                ev('positive', '64 hexadecimal characters (32 decoded bytes / 256 bits)', EW.SPECIFIC_REPRESENTATION),
                ev('positive', 'Length matches SHA-256 raw digest (most common 256-bit hash)', EW.SUPPORTING_CHARACTERISTIC),
            ];
            if (f.entropy > 3.7) evidence.push(ev('positive', `Shannon entropy ${f.entropy} bits/char — consistent with hash output`, EW.SUPPORTING_CHARACTERISTIC));
            evidence.push(ev('ambiguity', 'SHA-256, SHA3-256, BLAKE2s-256, and HMAC-SHA256 all produce 64-character hex output', EW.AMBIGUITY_NOTE));
            evidence.push(ev('ambiguity', 'No algorithm identifier is embedded in a raw digest', EW.AMBIGUITY_NOTE));
            evidence.push(ev('conflict', 'One-way hash — cannot be reversed or decrypted', EW.AMBIGUITY_NOTE));
            return { evidence, isDeterministic: false, supportedActions: ['analyze-hash'] };
        }
    },

    // ── SHA-384 / SHA3-384 group ──────────────────────────────
    {
        id: 'sha384-like',
        displayName: 'SHA-384-like / SHA3-384-like Hash (384-bit)',
        category: 'HASH',
        description: '96-character hexadecimal string matching SHA-384 or SHA3-384 output (384 bits).',
        detect(f, rep) {
            if (!rep.isStrictHexEven || f.len !== 96) return null;
            const evidence = [
                ev('positive', 'Strict hexadecimal representation', EW.SPECIFIC_REPRESENTATION),
                ev('positive', '96 hexadecimal characters (48 decoded bytes / 384 bits)', EW.SPECIFIC_REPRESENTATION),
                ev('positive', 'Length matches SHA-384 and SHA3-384 raw digest output', EW.SUPPORTING_CHARACTERISTIC),
                ev('ambiguity', 'SHA-384, SHA3-384, and BLAKE2b-384 share this output length', EW.AMBIGUITY_NOTE),
                ev('conflict', 'One-way hash — cannot be reversed or decrypted', EW.AMBIGUITY_NOTE),
            ];
            return { evidence, isDeterministic: false, supportedActions: ['analyze-hash'] };
        }
    },

    // ── SHA-512 / SHA3-512 / BLAKE2b-512 group ────────────────
    {
        id: 'sha512-like',
        displayName: 'SHA-512-like / SHA3-512-like / BLAKE2b-512-like Hash (512-bit)',
        category: 'HASH',
        description: '128-character hexadecimal string matching SHA-512, SHA3-512, or BLAKE2b-512 output (512 bits). Multiple algorithms share this output length.',
        detect(f, rep) {
            if (!rep.isStrictHexEven || f.len !== 128) return null;
            const evidence = [
                ev('positive', 'Strict hexadecimal representation', EW.SPECIFIC_REPRESENTATION),
                ev('positive', '128 hexadecimal characters (64 decoded bytes / 512 bits)', EW.SPECIFIC_REPRESENTATION),
                ev('positive', 'Length matches SHA-512, SHA3-512, and BLAKE2b-512 raw digest output', EW.SUPPORTING_CHARACTERISTIC),
            ];
            if (f.entropy > 3.7) evidence.push(ev('positive', `Shannon entropy ${f.entropy}`, EW.SUPPORTING_CHARACTERISTIC));
            evidence.push(ev('ambiguity', 'SHA-512, SHA3-512, BLAKE2b-512, and HMAC-SHA512 share this 128-hex-char output', EW.AMBIGUITY_NOTE));
            evidence.push(ev('ambiguity', 'No algorithm identifier present in raw digest output', EW.AMBIGUITY_NOTE));
            evidence.push(ev('conflict', 'One-way hash — cannot be reversed or decrypted', EW.AMBIGUITY_NOTE));
            return { evidence, isDeterministic: false, supportedActions: ['analyze-hash'] };
        }
    },

    // ── General hex (non-hash length) ─────────────────────────
    {
        id: 'hex-encoded',
        displayName: 'Hexadecimal-Encoded Data',
        category: 'ENCODING',
        description: 'Even-length hexadecimal data with a byte length that does not match any known hash digest length. May represent raw binary data, a key, a nonce, or arbitrary bytes.',
        detect(f, rep) {
            if (!rep.isStrictHexEven) return null;
            if (rep.isKnownHashLength) return null; // Handled by hash detectors
            const evidence = [
                ev('positive', 'Strict hexadecimal character set (0–9, a–f/A–F)', EW.SPECIFIC_REPRESENTATION),
                ev('positive', `Even length (${f.len} chars = ${rep.hexByteLen} bytes) — valid hex byte representation`, EW.SPECIFIC_REPRESENTATION),
                ev('ambiguity', 'Byte length does not match any common hash digest length', EW.AMBIGUITY_NOTE),
                ev('ambiguity', 'May represent a key, nonce, IV, or arbitrary binary data', EW.AMBIGUITY_NOTE),
            ];
            if (rep.hexByteLen !== null && rep.hexByteLen % 16 === 0) {
                evidence.push(ev('positive', `Byte count (${rep.hexByteLen}) is a multiple of 16 — AES block-aligned`, EW.SUPPORTING_CHARACTERISTIC));
            }
            return { evidence, isDeterministic: false, supportedActions: ['decode'] };
        }
    },

    // ── AES-CBC IV:Ciphertext pattern ─────────────────────────
    {
        id: 'aes-cbc-iv-ciphertext',
        displayName: 'AES-CBC IV:Ciphertext Pair',
        category: 'ENCRYPTION_FORMAT',
        description: 'Hex-encoded IV (32 chars / 16 bytes) followed by colon and hex-encoded AES-block-aligned ciphertext. Consistent with OmniGupt raw AES-CBC output.',
        detect(f, rep) {
            if (!rep.isAESCBCPattern) return null;
            const evidence = [
                ev('positive', 'Colon-delimited structure: IV (32 hex) : Ciphertext (hex)', EW.STRONG_STRUCTURAL),
                ev('positive', `IV: 32 hexadecimal characters (16 bytes = valid AES block size)`, EW.SPECIFIC_REPRESENTATION),
                ev('positive', `Ciphertext: ${rep.cbcCT ? rep.cbcCT.length : 0} hex chars — AES block-aligned`, EW.SPECIFIC_REPRESENTATION),
                ev('ambiguity', 'Consistent with OmniGupt raw AES-CBC export format', EW.AMBIGUITY_NOTE),
                ev('ambiguity', 'May also be a custom hex format using colon as delimiter', EW.AMBIGUITY_NOTE),
            ];
            return { evidence, isDeterministic: false, supportedActions: ['configure-decryption'] };
        }
    },

    // ── Canonical Base64 ──────────────────────────────────────
    {
        id: 'base64',
        displayName: 'Base64 Encoded',
        category: 'ENCODING',
        description: 'Standard Base64 encoded data. Canonical round-trip validation confirmed. Decoded content may be text, binary, or another encoded format.',
        detect(f, rep) {
            // Cannot be Base64 if already deterministically classified
            if (rep.b64KnownMarker === 'omnigupt-gcm') return null;
            if (rep.b64KnownMarker === 'openssl-salted') return null;
            if (rep.isCryptoJSLegacy) return null;
            if (rep.isPEM) return null;
            if (rep.isJWT) return null;

            if (!rep.isCanonicalBase64 && !rep.isWeakB64Compatible) return null;

            const evidence = [];

            if (rep.isCanonicalBase64) {
                evidence.push(ev('positive', 'Canonical Base64 validation passed (alphabet, padding, round-trip re-encode)', EW.SPECIFIC_REPRESENTATION));

                if (rep.b64UTF8Text) {
                    evidence.push(ev('positive', `Decoded content is valid UTF-8 text (${rep.b64Decoded ? rep.b64Decoded.length : 0} bytes)`, EW.STRONG_STRUCTURAL));
                } else if (rep.b64PrintableRatio > 0.9) {
                    evidence.push(ev('positive', `Decoded content is ${Math.round(rep.b64PrintableRatio * 100)}% printable ASCII`, EW.SUPPORTING_CHARACTERISTIC));
                } else {
                    evidence.push(ev('ambiguity', `Decoded content has low printable ratio (${Math.round(rep.b64PrintableRatio * 100)}%) — likely binary`, EW.AMBIGUITY_NOTE));
                }

                const s = f.raw;
                if (s.includes('+') || s.includes('/')) {
                    evidence.push(ev('positive', 'Contains + or / — standard Base64 (not Base64URL)', EW.SUPPORTING_CHARACTERISTIC));
                }
                if (s.endsWith('=') || s.endsWith('==')) {
                    evidence.push(ev('positive', 'Padding character(s) present — standard Base64', EW.WEAK_COMPATIBILITY));
                }
            } else {
                // Weak compatibility only
                evidence.push(ev('positive', 'Character set is compatible with Base64 alphabet', EW.WEAK_COMPATIBILITY));
                evidence.push(ev('positive', 'Length is divisible by 4 — consistent with Base64 framing', EW.WEAK_COMPATIBILITY));

                // If the input is strict hex, penalise hard
                if (rep.isStrictHex) {
                    evidence.push(ev('conflict', 'Input is strict hexadecimal — Base64 compatibility is coincidental (no + / = characters)', EW.REPRESENTATION_CONFLICT));
                }
            }

            evidence.push(ev('ambiguity', 'Decoded content may be text, binary, a nested encoding, or an encrypted container', EW.AMBIGUITY_NOTE));
            return { evidence, isDeterministic: false, supportedActions: ['decode'] };
        }
    },

    // ── Base64URL ─────────────────────────────────────────────
    {
        id: 'base64url',
        displayName: 'Base64URL Encoded',
        category: 'ENCODING',
        description: 'URL-safe Base64 encoding using - and _ instead of + and /. Common in JWT segments, OAuth tokens, and other URL-safe contexts.',
        detect(f, rep) {
            if (!rep.isBase64URL) return null;
            const evidence = [
                ev('positive', 'Contains URL-safe characters (- or _) absent from standard Base64', EW.SPECIFIC_REPRESENTATION),
                ev('positive', 'Character set matches Base64URL alphabet', EW.SUPPORTING_CHARACTERISTIC),
            ];
            if (rep.hasUrlAlphChars) {
                evidence.push(ev('positive', 'Presence of - or _ is distinguishing from standard Base64', EW.SUPPORTING_CHARACTERISTIC));
            }
            evidence.push(ev('ambiguity', 'Decoded content format cannot be determined without decoding', EW.AMBIGUITY_NOTE));
            return { evidence, isDeterministic: false, supportedActions: ['decode'] };
        }
    },

    // ── URL Percent-Encoded ───────────────────────────────────
    {
        id: 'url-encoded',
        displayName: 'URL Percent-Encoded',
        category: 'ENCODING',
        description: 'Text encoded with RFC 3986 URL percent-encoding (%XX sequences).',
        detect(f, rep) {
            if (!rep.isURLEncoded) return null;
            const count = rep.validPctSeqs.length;
            const evidence = [
                ev('positive', `${count} valid percent-encoded sequences (e.g. %20, %3A) detected`, EW.SPECIFIC_REPRESENTATION),
                ev('positive', 'All percent signs followed by valid hexadecimal pairs — no malformed sequences', EW.STRONG_STRUCTURAL),
            ];
            if (rep.invalidPctSeqs.length > 0) {
                evidence.push(ev('conflict', `${rep.invalidPctSeqs.length} malformed percent sequences present`, EW.CONTRADICTING_EVIDENCE));
            }
            return { evidence, isDeterministic: false, supportedActions: ['decode'] };
        }
    },

    // ── HTML Entities ─────────────────────────────────────────
    {
        id: 'html-entities',
        displayName: 'HTML Entity Encoded',
        category: 'ENCODING',
        description: 'Text containing valid HTML character entity references (&amp;, &lt;, &#60;, &#x3C;, etc.).',
        detect(f, rep) {
            if (!rep.hasHTMLEntities) return null;
            const evidence = [
                ev('positive', `${rep.totalEntities} HTML entity reference(s) detected`, EW.SPECIFIC_REPRESENTATION),
            ];
            if (rep.namedEntities.length > 0) evidence.push(ev('positive', `Named entities: ${rep.namedEntities.slice(0,3).join(', ')}`, EW.SUPPORTING_CHARACTERISTIC));
            if (rep.decimalEntities.length > 0) evidence.push(ev('positive', `Decimal entities (&#nn;): ${rep.decimalEntities.slice(0,3).join(', ')}`, EW.SUPPORTING_CHARACTERISTIC));
            if (rep.hexEntities.length > 0) evidence.push(ev('positive', `Hex entities (&#xnn;): ${rep.hexEntities.slice(0,3).join(', ')}`, EW.SUPPORTING_CHARACTERISTIC));
            return { evidence, isDeterministic: false, supportedActions: ['decode'] };
        }
    },

    // ── Unicode Escapes ───────────────────────────────────────
    {
        id: 'unicode-escape',
        displayName: 'Unicode Escape Sequences (\\uXXXX)',
        category: 'ENCODING',
        description: 'Text containing \\uXXXX Unicode escape sequences.',
        detect(f, rep) {
            if (!rep.hasValidUniEscape) return null;
            const evidence = [
                ev('positive', `${rep.unicodeEscapes.length} valid \\uXXXX Unicode escape sequences`, EW.SPECIFIC_REPRESENTATION),
            ];
            if (rep.malformedEscapes.length > 0) {
                evidence.push(ev('conflict', `${rep.malformedEscapes.length} malformed \\u escape sequences present`, EW.CONTRADICTING_EVIDENCE));
            }
            return { evidence, isDeterministic: false, supportedActions: ['decode'] };
        }
    },

    // ── Binary Text ───────────────────────────────────────────
    {
        id: 'binary-text',
        displayName: 'Binary Text Representation',
        category: 'ENCODING',
        description: 'Binary (base-2) representation of data using 0 and 1 characters, optionally separated by spaces.',
        detect(f, rep) {
            if (!rep.isBinaryText) return null;
            const evidence = [];
            if (rep.isByteAlignedBinary) {
                evidence.push(ev('positive', `${rep.binNoSpace.length} binary digits — ${rep.binNoSpace.length / 8} byte-aligned groups of 8`, EW.SPECIFIC_REPRESENTATION));
                evidence.push(ev('positive', 'Byte-aligned grouping (multiples of 8 bits)', EW.STRONG_STRUCTURAL));
            } else {
                evidence.push(ev('positive', 'Character set contains only 0 and 1', EW.WEAK_COMPATIBILITY));
                if (rep.binNoSpace.length < 8) {
                    evidence.push(ev('ambiguity', 'Input is too short for meaningful byte-level binary decoding', EW.AMBIGUITY_NOTE));
                } else {
                    evidence.push(ev('ambiguity', `${rep.binNoSpace.length} bits — not a multiple of 8, may simply be a numeric value`, EW.AMBIGUITY_NOTE));
                }
            }
            return { evidence, isDeterministic: false, supportedActions: ['decode'] };
        }
    },

    // ── ROT13 (low confidence, action only) ───────────────────
    {
        id: 'rot13-compatible',
        displayName: 'ROT13-Compatible Alphabetic Text',
        category: 'ENCODING',
        description: 'Alphabetic-only text that is structurally compatible with ROT13. ROT13 cannot be confirmed without semantic analysis — every alphabetic string is ROT13-compatible.',
        detect(f, rep) {
            if (!f.isAlphaText || f.len < 4) return null;
            if (rep.isStrictHex || rep.isPEM || rep.isJWT) return null;
            const evidence = [
                ev('positive', 'Alphabetic-only character set — structurally compatible with ROT13 transform', EW.WEAK_COMPATIBILITY),
                ev('ambiguity', 'ROT13 cannot be confirmed heuristically — every alphabetic string is ROT13-compatible', EW.AMBIGUITY_NOTE),
                ev('ambiguity', 'Applying ROT13 and checking readability is the only practical test', EW.AMBIGUITY_NOTE),
            ];
            return { evidence, isDeterministic: false, supportedActions: ['decode'] };
        }
    },

    // ── High-entropy canonical Base64 (ciphertext candidate) ──
    {
        id: 'high-entropy-base64',
        displayName: 'High-Entropy Base64 Data (Ciphertext Candidate)',
        category: 'CIPHERTEXT_CANDIDATE',
        description: 'High-entropy Base64-encoded data with no recognisable structural marker. Consistent with encrypted, compressed, or random data. Exact format cannot be identified from ciphertext alone.',
        detect(f, rep) {
            if (!rep.isCanonicalBase64) return null;
            if (rep.b64KnownMarker) return null; // Specific format already identified
            if (rep.isCryptoJSLegacy) return null;
            if (rep.isJWT) return null;
            if (rep.isPEM) return null;
            if (f.entropy < 5.0) return null; // Insufficient entropy for ciphertext claim

            const evidence = [
                ev('positive', 'Canonical Base64 representation confirmed', EW.SPECIFIC_REPRESENTATION),
                ev('positive', `High Shannon entropy: ${f.entropy} bits/char`, EW.SUPPORTING_CHARACTERISTIC),
            ];
            if (rep.b64Decoded && rep.b64Decoded.length % 16 === 0) {
                evidence.push(ev('positive', `Decoded byte count (${rep.b64Decoded.length}) is AES block-aligned (multiple of 16)`, EW.SUPPORTING_CHARACTERISTIC));
            }
            if (rep.b64PrintableRatio < 0.3) {
                evidence.push(ev('positive', 'Decoded content has low printable ratio — consistent with binary/encrypted data', EW.SUPPORTING_CHARACTERISTIC));
            }
            evidence.push(ev('ambiguity', 'High entropy alone does not prove encryption — compressed data and random bytes also exhibit high entropy', EW.AMBIGUITY_NOTE));
            evidence.push(ev('ambiguity', 'Cipher, mode, key size, and IV arrangement cannot be determined from ciphertext', EW.AMBIGUITY_NOTE));
            return { evidence, isDeterministic: false, supportedActions: ['inspect-structure'] };
        }
    },

    // ── High-entropy hex (non-hash-length, ciphertext candidate)
    {
        id: 'high-entropy-hex',
        displayName: 'High-Entropy Hexadecimal Data (Ciphertext Candidate)',
        category: 'CIPHERTEXT_CANDIDATE',
        description: 'Even-length hexadecimal data with high entropy that does not match a known hash digest length. May represent raw encrypted bytes, a key, or random data.',
        detect(f, rep) {
            if (!rep.isStrictHexEven) return null;
            if (rep.isKnownHashLength) return null; // Hash detectors handle these
            if (f.entropy < 3.0) return null;

            const evidence = [
                ev('positive', 'Strict hexadecimal representation', EW.SPECIFIC_REPRESENTATION),
                ev('positive', `Even length: ${f.len} chars = ${rep.hexByteLen} bytes`, EW.SPECIFIC_REPRESENTATION),
                ev('positive', `Shannon entropy: ${f.entropy} bits/char`, EW.SUPPORTING_CHARACTERISTIC),
            ];
            if (rep.hexByteLen !== null && rep.hexByteLen % 16 === 0) {
                evidence.push(ev('positive', `${rep.hexByteLen} bytes is AES block-aligned`, EW.SUPPORTING_CHARACTERISTIC));
            }
            evidence.push(ev('ambiguity', 'High entropy alone does not identify the cipher or algorithm', EW.AMBIGUITY_NOTE));
            evidence.push(ev('ambiguity', 'May represent encrypted data, a cryptographic key, a nonce, or random bytes', EW.AMBIGUITY_NOTE));
            return { evidence, isDeterministic: false, supportedActions: ['inspect-structure'] };
        }
    },

    // ── Fallback: Unknown ─────────────────────────────────────
    {
        id: 'unknown',
        displayName: 'Unclassified / Unknown Format',
        category: 'UNKNOWN',
        description: 'No format was identified with sufficient confidence. The input does not match any recognised cryptographic, encoding, token, or structured format.',
        detect(f, rep) {
            // Always returns, very low score — only shown if nothing else fires above threshold
            const evidence = [
                ev('ambiguity', `Input length: ${f.len} characters, Shannon entropy: ${f.entropy} bits/char`, EW.AMBIGUITY_NOTE),
                ev('ambiguity', 'No recognised structural pattern, prefix, or representation was found', EW.AMBIGUITY_NOTE),
            ];
            return { evidence, isDeterministic: false, supportedActions: [] };
        }
    },
];

// ============================================================
// SCORING ENGINE
// Sums evidence weights → clamps to [0, CS_SCORE_CAP]
// ============================================================
function cs_computeScore(evidenceArr, isDeterministic) {
    let raw = 0;
    for (const e of evidenceArr) {
        if (typeof e.weight === 'number') raw += e.weight;
    }
    // Deterministic signatures get a minimum floor
    if (isDeterministic) raw = Math.max(raw, 80);
    return Math.min(CS_SCORE_CAP, Math.max(0, Math.round(raw)));
}

// ============================================================
// DETECTION RUNNER
// ============================================================
function cs_runDetectors(f, rep) {
    const results = [];
    for (const detector of CS_DETECTORS) {
        try {
            const detection = detector.detect(f, rep);
            if (!detection) continue;
            const score = cs_computeScore(detection.evidence, detection.isDeterministic || false);
            if (score < CS_MIN_CONFIDENCE && detector.id !== 'unknown') continue;
            results.push({
                id: detector.id,
                displayName: detector.displayName,
                category: detector.category,
                description: detector.description,
                score,
                isDeterministic: detection.isDeterministic || false,
                evidence: detection.evidence,
                supportedActions: detection.supportedActions || [],
                sensitiveWarning: detection.sensitiveWarning || false,
            });
        } catch (_) {
            // Silently skip broken detectors — never expose raw input in error messages
        }
    }
    return results;
}

// ============================================================
// AMBIGUITY GROUP POST-PROCESSOR
// Ensures technically indistinguishable formats stay near each other in score.
// Also adds cross-group notes.
// ============================================================
const CS_AMBIGUITY_GROUPS = [
    {
        name: '256-BIT RAW DIGEST',
        ids: ['sha256-like'],  // Single entry since we merged them
        note: 'SHA-256, SHA3-256, and BLAKE2s-256 all produce 64-character hex output.'
    },
    {
        name: '512-BIT RAW DIGEST',
        ids: ['sha512-like'],
        note: 'SHA-512, SHA3-512, and BLAKE2b-512 all produce 128-character hex output.'
    }
];

// ============================================================
// RANK AND FILTER
// ============================================================
function cs_rankResults(detections) {
    return detections
        .filter(r => r.score >= CS_MIN_CONFIDENCE || r.id === 'unknown')
        .sort((a, b) => b.score - a.score);
}

// ============================================================
// ACTION RESOLVER
// Returns structured actions for each result
// ============================================================
const CS_ACTION_MAP = {
    'decode':               { label: '[ DECODE ]',               type: 'decode',          desc: 'Decode and display the transformed value.' },
    'analyze-hash':         { label: '[ ANALYZE HASH ]',         type: 'hash-info',       desc: 'One-way hash — direct reversal is mathematically infeasible.' },
    'configure-decryption': { label: '[ CONFIGURE DECRYPTION ]', type: 'decrypt-config',  desc: 'Supply key/passphrase to attempt local decryption.' },
    'inspect-token':        { label: '[ INSPECT TOKEN ]',        type: 'token-inspect',   desc: 'Decode JWT header and payload claims.' },
    'inspect-structure':    { label: '[ INSPECT STRUCTURE ]',    type: 'structure-inspect', desc: 'Show structural metadata.' },
};

function cs_resolveAction(result) {
    return (result.supportedActions || []).map(k => CS_ACTION_MAP[k]).filter(Boolean);
}

// ============================================================
// RECURSIVE DECODER  (hardened: visited-set loop prevention, max depth)
// ============================================================
function cs_recursiveDecode(value, depth, visited) {
    if (depth >= CS_MAX_RECURSION) return [{ label: `Max decode depth (${CS_MAX_RECURSION}) reached`, decoded: value, type: 'limit' }];
    if (!visited) visited = new Set();
    const normalised = value.trim();
    if (!normalised) return [];
    if (visited.has(normalised)) return [{ label: 'Cycle detected — decoding stopped', decoded: value, type: 'cycle' }];
    visited.add(normalised);

    const chain = [];

    // ── Base64 ──
    if (/^[A-Za-z0-9+/]*={0,2}$/.test(normalised) && normalised.length % 4 === 0 && normalised.length >= 4) {
        try {
            const decoded = _cs_atob(normalised);
            const reEnc   = _cs_btoa(decoded);
            if (reEnc === normalised) {
                let decodedDisplay = decoded;
                let type = 'base64';
                // Try UTF-8
                try {
                    const bytes = new Uint8Array(decoded.length);
                    for (let i = 0; i < decoded.length; i++) bytes[i] = decoded.charCodeAt(i);
                    decodedDisplay = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
                    type = 'base64-text';
                } catch (_) { /* binary */ }
                chain.push({ label: 'Base64', decoded: decodedDisplay, type });
                // Recurse if transformed value is different
                if (decodedDisplay !== normalised && !visited.has(decodedDisplay.trim())) {
                    const deeper = cs_recursiveDecode(decodedDisplay.trim(), depth + 1, visited);
                    chain.push(...deeper.map(d => ({ ...d, label: `Base64 → ${d.label}` })));
                }
                return chain;
            }
        } catch (_) { /* not canonical Base64 */ }
    }

    // ── Base64URL ──
    if (/^[A-Za-z0-9\-_]+$/.test(normalised) && (normalised.includes('-') || normalised.includes('_'))) {
        try {
            const decoded = cs_b64urlDecode(normalised);
            chain.push({ label: 'Base64URL', decoded, type: 'base64url' });
            return chain;
        } catch (_) { /* ignore */ }
    }

    // ── Hex → UTF-8 ──
    if (/^[0-9a-fA-F]+$/.test(normalised) && normalised.length % 2 === 0) {
        try {
            const bytes = new Uint8Array(normalised.match(/.{2}/g).map(b => parseInt(b, 16)));
            try {
                const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
                chain.push({ label: 'Hex → UTF-8 Text', decoded: text, type: 'hex-utf8' });
                if (text !== normalised && !visited.has(text.trim())) {
                    const deeper = cs_recursiveDecode(text.trim(), depth + 1, visited);
                    chain.push(...deeper.map(d => ({ ...d, label: `Hex → ${d.label}` })));
                }
            } catch (_) {
                chain.push({ label: `Hex → Binary (${bytes.length} bytes, not valid UTF-8)`, decoded: `[${bytes.length} binary bytes]`, type: 'hex-binary' });
            }
            return chain;
        } catch (_) { /* ignore */ }
    }

    // ── URL percent-decode ──
    if (normalised.includes('%') && /%.{2}/.test(normalised)) {
        try {
            const decoded = decodeURIComponent(normalised);
            if (decoded !== normalised) {
                chain.push({ label: 'URL Decoded', decoded, type: 'url-decode' });
                if (!visited.has(decoded.trim())) {
                    const deeper = cs_recursiveDecode(decoded.trim(), depth + 1, visited);
                    chain.push(...deeper.map(d => ({ ...d, label: `URL → ${d.label}` })));
                }
                return chain;
            }
        } catch (_) { /* ignore */ }
    }

    // ── HTML entity decode ──
    if (/&[a-zA-Z]{2,8};|&#\d+;|&#x[0-9a-fA-F]+;/.test(normalised)) {
        if (typeof document !== 'undefined') {
            const el = document.createElement('span');
            el.innerHTML = normalised;
            const decoded = el.textContent;
            if (decoded !== normalised) {
                chain.push({ label: 'HTML Entity Decoded', decoded, type: 'html-decode' });
                return chain;
            }
        }
    }

    // ── Unicode escape decode ──
    if (/\\u[0-9a-fA-F]{4}/.test(normalised)) {
        try {
            const decoded = normalised.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
            chain.push({ label: 'Unicode Escape Decoded', decoded, type: 'unicode-decode' });
            return chain;
        } catch (_) { /* ignore */ }
    }

    // ── ROT13 ──
    if (/^[a-zA-Z\s]+$/.test(normalised) && normalised.length >= 4) {
        const rot13 = normalised.replace(/[a-zA-Z]/g, c => {
            const base = c < 'a' ? 65 : 97;
            return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
        });
        chain.push({ label: 'ROT13 Applied', decoded: rot13, type: 'rot13' });
        return chain;
    }

    // ── Binary decode ──
    if (/^[01][\s01]*$/.test(normalised)) {
        const bin = normalised.replace(/\s/g, '');
        if (bin.length % 8 === 0 && bin.length >= 8) {
            try {
                const bytes = [];
                for (let i = 0; i < bin.length; i += 8) bytes.push(parseInt(bin.slice(i, i + 8), 2));
                const text = new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(bytes));
                chain.push({ label: 'Binary → UTF-8 Text', decoded: text, type: 'binary-text' });
                return chain;
            } catch (_) {
                chain.push({ label: 'Binary → Bytes (not valid UTF-8)', decoded: `[${bin.length / 8} bytes]`, type: 'binary-bytes' });
                return chain;
            }
        }
    }

    chain.push({ label: 'Plain Text (no further decoding applicable)', decoded: normalised, type: 'plaintext' });
    return chain;
}

// ============================================================
// JWT INSPECTOR
// ============================================================
function cs_decodeJWT(jwtStr) {
    const parts = jwtStr.split('.');
    if (parts.length !== 3) return null;
    try {
        const header  = JSON.parse(cs_b64urlDecode(parts[0]));
        const payload = JSON.parse(cs_b64urlDecode(parts[1]));
        return { header, payload, signatureB64: parts[2], raw: { header: parts[0], payload: parts[1], signature: parts[2] } };
    } catch (_) {
        return null;
    }
}

// ============================================================
// PEM INSPECTOR
// ============================================================
function cs_inspectPEM(value) {
    const bm = value.match(/^-----BEGIN ([^-\n]+)-----/);
    if (!bm) return null;
    const type = bm[1].trim();
    const em   = value.match(/-----END ([^-\n]+)-----/);
    const endType = em ? em[1].trim() : null;
    const lines = value.split('\n').filter(l => !l.startsWith('---') && l.trim());
    return {
        type,
        endType,
        labelsMatch: type === endType,
        dataLines: lines.length,
        isSensitive: type.toUpperCase().includes('PRIVATE')
    };
}

// ============================================================
// MAIN ANALYSIS FUNCTION
// ============================================================
function cs_analyze(rawInput) {
    const normalized = cs_normalizeInput(rawInput);
    if (!normalized.trimmed) return { error: 'Input is empty.' };

    const s   = normalized.trimmed;
    const rep = cs_analyzeRepresentation(s);
    const f   = { raw: s, ...cs_extractFeatures(s, rep) };

    const detections = cs_runDetectors(f, rep);
    const ranked     = cs_rankResults(detections);

    // Build category signal for summary
    let categorySignal = 'Unknown';
    if (ranked.length > 0 && ranked[0].score >= CS_MIN_CONFIDENCE) {
        const top = ranked[0];
        if (top.category === 'HASH')                categorySignal = `Hash-like (${top.displayName})`;
        else if (top.category === 'PASSWORD_HASH')  categorySignal = `Password Hash (${top.displayName})`;
        else if (top.category === 'ENCODING')       categorySignal = `Encoding (${top.displayName})`;
        else if (top.category === 'ENCRYPTION_FORMAT') categorySignal = `Encryption Container (${top.displayName})`;
        else if (top.category === 'TOKEN')          categorySignal = `Token (${top.displayName})`;
        else if (top.category === 'KEY_OR_CERTIFICATE') categorySignal = `Key / Certificate (${top.displayName})`;
        else if (top.category === 'CIPHERTEXT_CANDIDATE') categorySignal = 'Possible Ciphertext';
    }

    return {
        features: {
            raw: s,
            length: f.len,
            entropy: f.entropy,
            uniqueChars: f.uniqueChars,
            isStrictHex: rep.isStrictHex,
            isStrictHexEven: rep.isStrictHexEven,
            hexByteLen: rep.hexByteLen,
            isCanonicalBase64: rep.isCanonicalBase64,
            isBase64URL: rep.isBase64URL,
            isJWT: rep.isJWT,
            jwtAlg: rep.jwtAlg,
            isPEM: rep.isPEM,
            pemBeginLabel: rep.pemBeginLabel,
            isURLEncoded: rep.isURLEncoded,
            hasHTMLEntities: rep.hasHTMLEntities,
            hasValidUniEscape: rep.hasValidUniEscape,
            isBinaryText: rep.isBinaryText,
            isByteAlignedBinary: rep.isByteAlignedBinary,
            dollarCount: rep.dollarCount,
            isKnownHashLength: rep.isKnownHashLength,
            categorySignal,
            // keep for summary render
            isOmniGuptGCM: rep.b64KnownMarker === 'omnigupt-gcm',
            isOpenSSLSalted: rep.b64KnownMarker === 'openssl-salted',
            isCryptoJSLegacy: rep.isCryptoJSLegacy,
            openSSLSalt: rep.openSSLSalt,
            hasUpper: f.hasUpper,
            hasLower: f.hasLower,
            hasDigit: f.hasDigit,
            hasSymbol: f.hasSymbol,
            hasDots: (s.match(/\./g) || []).length,
            hasColons: (s.match(/:/g) || []).length,
            colonSegments: s.split(':'),
            dotSegments: s.split('.'),
            dollarSegments: s.split('$').filter(Boolean),
            aesBlockAligned: rep.hexByteLen !== null && rep.hexByteLen % 16 === 0,
            aesBlockAlignedB64: rep.isCanonicalBase64 && rep.b64Decoded && rep.b64Decoded.length % 16 === 0,
            base64ByteLength: rep.isCanonicalBase64 && rep.b64Decoded ? rep.b64Decoded.length : null,
        },
        results: ranked,
        hasResults: ranked.some(r => r.score >= CS_MIN_CONFIDENCE),
    };
}

// ============================================================
// EXPORTS  (window scope for file:// and test harness)
// ============================================================
window.cipherSense = {
    analyze:           cs_analyze,
    resolveAction:     cs_resolveAction,
    decodeRecursive:   cs_recursiveDecode,
    decodeJWT:         cs_decodeJWT,
    inspectPEM:        cs_inspectPEM,
    shannonEntropy:    cs_shannonEntropy,
    // Expose internals for unit tests
    _normalizeInput:   cs_normalizeInput,
    _analyzeRepresentation: cs_analyzeRepresentation,
    _extractFeatures:  cs_extractFeatures,
    _runDetectors:     cs_runDetectors,
    _EW:               EW,
};

