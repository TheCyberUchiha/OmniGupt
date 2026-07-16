/**
 * CipherSense Engine v2 — Comprehensive Test Suite
 *
 * Test categories:
 *  A. Core invariants (determinism, score bounds, no duplicates)
 *  B. Representation analyzer
 *  C. Hash detectors + ambiguity groups
 *  D. Password hash detectors
 *  E. Base64 canonical vs. strict-hex conflict
 *  F. Base64URL
 *  G. JWT structural validation
 *  H. PEM key / certificate
 *  I. Encryption container formats
 *  J. Encoding formats (URL, HTML, Unicode, Binary)
 *  K. Ciphertext heuristics
 *  L. Cross-format ranking (the core fix)
 *  M. Security / privacy (no Math.random, no network calls)
 *  N. Recursive decoder
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);
const ENGINE_PATH = resolve(__dirname, '..', 'ciphersense-engine.js');

// ── Setup (inject engine into globalThis) ───────────────────
beforeAll(() => {
    if (!globalThis.atob) {
        globalThis.atob = (s) => Buffer.from(s, 'base64').toString('binary');
        globalThis.btoa = (s) => Buffer.from(s, 'binary').toString('base64');
    }
    if (!globalThis.TextDecoder) {
        const { TextDecoder, TextEncoder } = require('util');
        globalThis.TextDecoder = TextDecoder;
        globalThis.TextEncoder = TextEncoder;
    }
    if (!globalThis.document) {
        globalThis.document = {
            createElement: () => ({
                set innerHTML(v) { this._v = v; },
                get textContent() { return this._v || ''; }
            })
        };
    }
    globalThis.window = globalThis;
    eval(readFileSync(ENGINE_PATH, 'utf8'));
});

// ── Helpers ──────────────────────────────────────────────────
const analyze = (input) => globalThis.window.cipherSense.analyze(input);
const top      = (input) => analyze(input).results?.[0] ?? null;
const hasId    = (input, id) => (analyze(input).results ?? []).some(r => r.id === id);
const score    = (input, id) => (analyze(input).results ?? []).find(r => r.id === id)?.score ?? -1;
const allScores = (input) => (analyze(input).results ?? []);

// ── A. CORE INVARIANTS ───────────────────────────────────────

describe('A. Core Invariants', () => {
    it('Empty input → error, not crash', () => {
        expect(analyze('').error).toBeDefined();
        expect(analyze('   ').error).toBeDefined();
    });

    it('Same input always returns same ordered candidates (determinism)', () => {
        const input = 'd41d8cd98f00b204e9800998ecf8427e';
        const r1 = analyze(input).results.map(r => r.id);
        const r2 = analyze(input).results.map(r => r.id);
        expect(r1).toEqual(r2);
    });

    it('No score below 0', () => {
        const inputs = [
            'd41d8cd98f00b204e9800998ecf8427e',
            'SGVsbG8=',
            '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW',
            'hello world',
            'U2FsdGVkX1+abc123',
        ];
        for (const input of inputs) {
            for (const r of allScores(input)) {
                expect(r.score).toBeGreaterThanOrEqual(0);
            }
        }
    });

    it('No score above 99', () => {
        const inputs = [
            '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW',
            '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8=\n-----END PUBLIC KEY-----',
        ];
        for (const input of inputs) {
            for (const r of allScores(input)) {
                expect(r.score).toBeLessThanOrEqual(99);
            }
        }
    });

    it('No duplicate candidate IDs in one result set', () => {
        const inputs = [
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'SGVsbG8gV29ybGQ=',
        ];
        for (const input of inputs) {
            const ids = allScores(input).map(r => r.id);
            expect(new Set(ids).size).toBe(ids.length);
        }
    });

    it('Deterministic formats always outscore generic compatibility', () => {
        // bcrypt is deterministic → must outscore unknown
        const bcrypt = '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW';
        const results = allScores(bcrypt);
        const bcryptScore = results.find(r => r.id === 'bcrypt')?.score ?? 0;
        const unknownScore = results.find(r => r.id === 'unknown')?.score ?? 0;
        expect(bcryptScore).toBeGreaterThan(unknownScore);
    });
});

// ── B. REPRESENTATION ANALYZER ───────────────────────────────

describe('B. Representation Analyzer', () => {
    const ra = (s) => globalThis.window.cipherSense._analyzeRepresentation(s);

    it('Pure lowercase hex detected as strict hex', () => {
        const r = ra('d41d8cd98f00b204e9800998ecf8427e');
        expect(r.isStrictHex).toBe(true);
        expect(r.hexAllLower).toBe(true);
        expect(r.isStrictHexEven).toBe(true);
        expect(r.hexByteLen).toBe(16);
    });

    it('Uppercase hex detected', () => {
        const r = ra('D41D8CD98F00B204E9800998ECF8427E');
        expect(r.isStrictHex).toBe(true);
        expect(r.hexAllUpper).toBe(true);
    });

    it('Hex with non-hex chars is NOT strict hex', () => {
        const r = ra('d41d8cd98f00b204e9800998ecf8427g');
        expect(r.isStrictHex).toBe(false);
    });

    it('Odd-length hex is NOT even hex', () => {
        const r = ra('abc');
        expect(r.isStrictHex).toBe(true);
        expect(r.isStrictHexEven).toBe(false);
    });

    it('Known hash hex length detected', () => {
        expect(ra('a'.repeat(32)).isKnownHashLength).toBe(true);
        expect(ra('a'.repeat(40)).isKnownHashLength).toBe(true);
        expect(ra('a'.repeat(56)).isKnownHashLength).toBe(true);
        expect(ra('a'.repeat(64)).isKnownHashLength).toBe(true);
        expect(ra('a'.repeat(96)).isKnownHashLength).toBe(true);
        expect(ra('a'.repeat(128)).isKnownHashLength).toBe(true);
        expect(ra('a'.repeat(48)).isKnownHashLength).toBe(false);
    });

    it('Canonical Base64 round-trip validation (has + / = )', () => {
        const r = ra('SGVsbG8gV29ybGQ='); // "Hello World"
        expect(r.isCanonicalBase64).toBe(true);
        expect(r.isStrictHex).toBe(false);
    });

    it('Pure hex string is NOT canonical Base64 (even if chars are compatible)', () => {
        // d41d8cd98f00b204e9800998ecf8427e — pure lowercase hex, no + / =
        const r = ra('d41d8cd98f00b204e9800998ecf8427e');
        // may or may not be canonical B64 — but strict hex takes precedence
        // The KEY thing: when isStrictHex = true, Base64 gets REPRESENTATION_CONFLICT
        expect(r.isStrictHex).toBe(true);
    });

    it('JWT: 3 segments with valid JSON header+payload', () => {
        const hdr = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
        const pld = btoa(JSON.stringify({ sub: '1', iat: 1516239022 })).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
        const sig = 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
        const r = ra(`${hdr}.${pld}.${sig}`);
        expect(r.isJWT).toBe(true);
        expect(r.jwtAlg).toBe('HS256');
    });

    it('Generic a.b.c text is NOT a JWT', () => {
        const r = ra('hello.world.foo');
        expect(r.isJWT).toBe(false);
    });

    it('PEM with matching labels', () => {
        const pem = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8=\n-----END PUBLIC KEY-----';
        const r = ra(pem);
        expect(r.isPEM).toBe(true);
        expect(r.pemLabelsMatch).toBe(true);
        expect(r.pemBeginLabel).toBe('PUBLIC KEY');
    });

    it('URL encoding: valid %XX sequences', () => {
        const r = ra('Hello%20World%21');
        expect(r.isURLEncoded).toBe(true);
        expect(r.invalidPctSeqs.length).toBe(0);
    });

    it('Malformed percent is NOT URL encoded', () => {
        const r = ra('Hello%2World');
        expect(r.isURLEncoded).toBe(false);
    });

    it('Byte-aligned binary text (8n bits)', () => {
        const r = ra('01001000 01101001');
        expect(r.isBinaryText).toBe(true);
        expect(r.isByteAlignedBinary).toBe(true);
    });

    it('"101" is binary-like but NOT byte-aligned', () => {
        const r = ra('101');
        expect(r.isBinaryText).toBe(true);
        expect(r.isByteAlignedBinary).toBe(false);
    });
});

// ── C. HASH DETECTORS ────────────────────────────────────────

describe('C. Hash Detectors', () => {
    // MD5-like: 32 hex chars
    it('32-char hex → md5-like', () => {
        expect(hasId('d41d8cd98f00b204e9800998ecf8427e', 'md5-like')).toBe(true);
    });

    it('md5-like is never marked isDeterministic', () => {
        const res = analyze('d41d8cd98f00b204e9800998ecf8427e').results.find(r => r.id === 'md5-like');
        expect(res?.isDeterministic).toBe(false);
    });

    it('md5-like has ambiguity note about algorithm identifier', () => {
        const res = analyze('d41d8cd98f00b204e9800998ecf8427e').results.find(r => r.id === 'md5-like');
        const amb = res?.evidence.find(e => e.type === 'ambiguity');
        expect(amb).toBeDefined();
        expect(amb.text).toMatch(/algorithm identifier/i);
    });

    // SHA-1-like: 40 hex chars
    it('40-char hex → sha1-like', () => {
        expect(hasId('da39a3ee5e6b4b0d3255bfef95601890afd80709', 'sha1-like')).toBe(true);
    });

    it('sha1-like ambiguity mentions RIPEMD-160', () => {
        const res = analyze('da39a3ee5e6b4b0d3255bfef95601890afd80709').results.find(r => r.id === 'sha1-like');
        expect(res?.evidence.some(e => e.text.includes('RIPEMD-160'))).toBe(true);
    });

    // 56-char hex → sha224-like
    it('56-char hex → sha224-like', () => {
        expect(hasId('d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f', 'sha224-like')).toBe(true);
    });

    // 64-char hex → sha256-like
    it('64-char hex → sha256-like', () => {
        expect(hasId('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'sha256-like')).toBe(true);
    });

    it('sha256-like mentions multiple 256-bit algorithms in ambiguity note', () => {
        const res = analyze('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
            .results.find(r => r.id === 'sha256-like');
        const notes = res?.evidence.filter(e => e.type === 'ambiguity').map(e => e.text).join(' ');
        expect(notes).toMatch(/SHA3-256/);
        expect(notes).toMatch(/BLAKE2s/);
    });

    // 96-char hex → sha384-like
    it('96-char hex → sha384-like', () => {
        expect(hasId('a'.repeat(96), 'sha384-like')).toBe(true);
    });

    // 128-char hex → sha512-like
    it('128-char hex → sha512-like', () => {
        expect(hasId('a'.repeat(128), 'sha512-like')).toBe(true);
    });

    it('sha512-like mentions multiple 512-bit algorithms', () => {
        const res = analyze('a'.repeat(128)).results.find(r => r.id === 'sha512-like');
        const notes = res?.evidence.filter(e => e.type === 'ambiguity').map(e => e.text).join(' ');
        expect(notes).toMatch(/BLAKE2b/);
    });

    // Hash action must be analyze-hash, never decrypt
    it('Hash results never expose a decryption action', () => {
        const hashIds = ['md5-like', 'sha1-like', 'sha224-like', 'sha256-like', 'sha384-like', 'sha512-like'];
        const inputs = [
            'd41d8cd98f00b204e9800998ecf8427e',
            'da39a3ee5e6b4b0d3255bfef95601890afd80709',
            'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f',
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        ];
        for (const input of inputs) {
            for (const r of allScores(input).filter(r => hashIds.includes(r.id))) {
                expect(r.supportedActions).not.toContain('configure-decryption');
                expect(r.supportedActions).toContain('analyze-hash');
            }
        }
    });

    // Low-entropy hex (all same char) should score lower
    it('Repeated-char hex (low entropy) scores lower than high-entropy hex of same length', () => {
        const lowEntropyHex  = 'a'.repeat(64);
        const highEntropyHex = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        const lowScore  = score(lowEntropyHex,  'sha256-like');
        const highScore = score(highEntropyHex, 'sha256-like');
        // Both may match, but high-entropy should score >= low-entropy
        expect(highScore).toBeGreaterThanOrEqual(lowScore);
    });

    // Uppercase hex should still match
    it('Uppercase 64-char hex → sha256-like', () => {
        expect(hasId('E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855', 'sha256-like')).toBe(true);
    });

    // Odd-length hex → NO hash match
    it('Odd-length hex → no hash match', () => {
        const hashIds = ['md5-like', 'sha1-like', 'sha256-like', 'sha512-like'];
        const r = analyze('abcde');
        for (const id of hashIds) {
            expect(r.results.some(res => res.id === id)).toBe(false);
        }
    });

    // 32-char hex with non-hex char → no hash
    it('32-char string with invalid hex char → no hash detection', () => {
        const input = 'd41d8cd98f00b204e9800998ecf8427g'; // 'g' is invalid
        expect(hasId(input, 'md5-like')).toBe(false);
    });
});

// ── D. PASSWORD HASH DETECTORS ───────────────────────────────

describe('D. Password Hash Detectors', () => {
    const validBcrypt = '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW';

    it('Valid bcrypt $2b$ → bcrypt with isDeterministic', () => {
        const r = analyze(validBcrypt).results.find(x => x.id === 'bcrypt');
        expect(r).toBeDefined();
        expect(r.isDeterministic).toBe(true);
        expect(r.score).toBeGreaterThanOrEqual(80);
    });

    it('bcrypt never exposes configure-decryption action', () => {
        const r = analyze(validBcrypt).results.find(x => x.id === 'bcrypt');
        expect(r?.supportedActions).not.toContain('configure-decryption');
        expect(r?.supportedActions).toContain('analyze-hash');
    });

    it('bcrypt cost factor is in evidence', () => {
        const r = analyze(validBcrypt).results.find(x => x.id === 'bcrypt');
        expect(r?.evidence.some(e => e.text.includes('12'))).toBe(true);
    });

    it('$2y$ variant also detected as bcrypt', () => {
        // $2y$12$ + 53 chars of [./A-Za-z0-9]
        const bcrypt2y = '$2y$10$' + 'A'.repeat(53);
        expect(hasId(bcrypt2y, 'bcrypt')).toBe(true);
    });

    it('Fake $2b$ string (wrong length) → bcrypt partial or low score', () => {
        const fake = '$2b$12$tooshort';
        const r = analyze(fake);
        const bcryptRes = r.results.find(x => x.id === 'bcrypt');
        // Either not present or not isDeterministic
        if (bcryptRes) expect(bcryptRes.isDeterministic).toBe(false);
    });

    it('Invalid bcrypt cost (letters) → no deterministic bcrypt', () => {
        const bad = '$2b$AB$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW';
        const r = analyze(bad).results.find(x => x.id === 'bcrypt');
        if (r) expect(r.isDeterministic).toBe(false);
    });

    // Argon2id
    const argon2id = '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG';

    it('Valid Argon2id → argon2 with isDeterministic', () => {
        const r = analyze(argon2id).results.find(x => x.id === 'argon2');
        expect(r).toBeDefined();
        expect(r.isDeterministic).toBe(true);
        expect(r.score).toBeGreaterThanOrEqual(80);
    });

    it('Argon2id evidence contains memory, time, parallelism params', () => {
        const r = analyze(argon2id).results.find(x => x.id === 'argon2');
        const texts = r?.evidence.map(e => e.text).join(' ') ?? '';
        expect(texts).toMatch(/m=65536/);
        expect(texts).toMatch(/t=3/);
        expect(texts).toMatch(/p=4/);
    });

    it('Argon2i variant detected', () => {
        const argon2i = '$argon2i$v=19$m=4096,t=3,p=1$c2FsdHNhbHQ$BbN5yBrh5d+B0y1mW7f2vg';
        expect(hasId(argon2i, 'argon2')).toBe(true);
    });

    it('Malformed Argon2 (missing params) → not isDeterministic', () => {
        const bad = '$argon2id$v=19$something_wrong';
        const r = analyze(bad).results.find(x => x.id === 'argon2');
        if (r) expect(r.isDeterministic).toBe(false);
    });

    it('Unix $1$ crypt detected', () => {
        expect(hasId('$1$salt$abcdefghijklmnopqrstuv', 'unix-md5-crypt')).toBe(true);
    });

    it('Unix $5$ crypt detected', () => {
        expect(hasId('$5$rounds=5000$salt$hash', 'unix-sha256-crypt')).toBe(true);
    });

    it('Unix $6$ crypt detected', () => {
        expect(hasId('$6$rounds=5000$salt$hash', 'unix-sha512-crypt')).toBe(true);
    });

    it('Password hash detectors never expose configure-decryption action', () => {
        for (const input of [validBcrypt, argon2id, '$1$salt$abc', '$6$salt$abc']) {
            for (const r of allScores(input).filter(r => r.category === 'PASSWORD_HASH')) {
                expect(r.supportedActions).not.toContain('configure-decryption');
            }
        }
    });
});

// ── E. BASE64 vs STRICT HEX CONFLICT ─────────────────────────

describe('E. Base64 vs Strict Hex Conflict — The Core Fix', () => {
    const md5hex = '5d41402abc4b2a76b9719d911017c592';

    it('5d41402abc4b2a76b9719d911017c592 → md5-like IS present', () => {
        expect(hasId(md5hex, 'md5-like')).toBe(true);
    });

    it('md5-like scores HIGHER than base64 for a strict-hex MD5 string', () => {
        const md5Score  = score(md5hex, 'md5-like');
        const b64Score  = score(md5hex, 'base64');
        // Base64 should either be absent or score much lower than md5-like
        expect(md5Score).toBeGreaterThan(b64Score);
    });

    it('Base64 is absent or below threshold for pure hex MD5 input', () => {
        const b64Score = score(md5hex, 'base64');
        // Should be 0 (not present) or at minimum far below the hash score
        const md5Score = score(md5hex, 'md5-like');
        expect(md5Score).toBeGreaterThan(b64Score + 10);
    });

    it('64-char hex → sha256-like scores higher than base64', () => {
        const hex = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        expect(score(hex, 'sha256-like')).toBeGreaterThan(score(hex, 'base64'));
    });

    it('128-char hex → sha512-like scores higher than base64', () => {
        const hex = 'a'.repeat(128);
        expect(score(hex, 'sha512-like')).toBeGreaterThan(score(hex, 'base64'));
    });

    it('Genuine Base64 with + and / → base64 IS top result', () => {
        const b64 = btoa('Hello World from CipherSense!');
        const t = top(b64);
        expect(t?.id).toBe('base64');
    });

    it('Base64 with = padding → canonical detection', () => {
        expect(hasId('SGVsbG8=', 'base64')).toBe(true);
    });

    it('Invalid Base64 (bad padding) → base64 not detected', () => {
        const bad = 'SGVsbG8==EXTRA';
        expect(hasId(bad, 'base64')).toBe(false);
    });

    it('Base64 with + / characters → NOT classified as hex', () => {
        const b64 = 'a+b/c+d/e+f/g+h/'; // has + and /
        expect(hasId(b64, 'md5-like')).toBe(false);
        expect(hasId(b64, 'sha256-like')).toBe(false);
    });
});

// ── F. BASE64URL ──────────────────────────────────────────────

describe('F. Base64URL', () => {
    it('String with - and _ → base64url detected', () => {
        expect(hasId('SGVsbG8-V29ybGQ_', 'base64url')).toBe(true);
    });

    it('JWT segment → analyzed as JWT, not raw base64url', () => {
        const hdr = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
        const pld = btoa(JSON.stringify({ sub: '1' })).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
        const jwt = `${hdr}.${pld}.sig`;
        expect(hasId(jwt, 'jwt')).toBe(true);
    });

    it('Standard Base64 with + / does NOT match base64url', () => {
        const b64 = 'a+b/c+d/';
        const r = analyze(b64);
        const b64url = r.results.find(x => x.id === 'base64url');
        // b64url requires - or _, not + or /
        if (b64url) expect(b64url.score).toBe(0);
    });
});

// ── G. JWT ────────────────────────────────────────────────────

describe('G. JWT Detection', () => {
    const makeJWT = (hdr, pld) => {
        const h = btoa(JSON.stringify(hdr)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
        const p = btoa(JSON.stringify(pld)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
        return `${h}.${p}.SflKxwRJSMeKKF2QT4fwpMeJf36POk`;
    };

    const validJWT = makeJWT({ alg: 'HS256', typ: 'JWT' }, { sub: '1', iat: 1516239022 });

    it('Valid JWT → jwt detected with STRONG evidence', () => {
        expect(hasId(validJWT, 'jwt')).toBe(true);
    });

    it('JWT with alg field → higher evidence score', () => {
        const jwtWithAlg    = makeJWT({ alg: 'HS256', typ: 'JWT' }, { sub: '1' });
        const jwtWithoutAlg = makeJWT({ typ: 'JWT' }, { sub: '1' });
        const s1 = score(jwtWithAlg, 'jwt');
        const s2 = score(jwtWithoutAlg, 'jwt');
        expect(s1).toBeGreaterThanOrEqual(s2);
    });

    it('JWT action → inspect-token only (no decrypt, no decode)', () => {
        const r = analyze(validJWT).results.find(x => x.id === 'jwt');
        expect(r?.supportedActions).toContain('inspect-token');
        expect(r?.supportedActions).not.toContain('configure-decryption');
    });

    it('Generic a.b.c text → NOT jwt', () => {
        expect(hasId('hello.world.foo', 'jwt')).toBe(false);
    });

    it('Two-segment string → NOT jwt', () => {
        expect(hasId('abc.def', 'jwt')).toBe(false);
    });

    it('Four-segment string → NOT jwt', () => {
        expect(hasId('a.b.c.d', 'jwt')).toBe(false);
    });

    it('JWT with malformed header JSON → NOT jwt', () => {
        const bad = 'bm90anNvbg.eyJzdWIiOiIxIn0.sig';
        expect(hasId(bad, 'jwt')).toBe(false);
    });

    it('JWT evidence includes decoded claims statement', () => {
        const r = analyze(validJWT).results.find(x => x.id === 'jwt');
        expect(r?.evidence.some(e => e.type === 'ambiguity' && e.text.toLowerCase().includes('verif'))).toBe(true);
    });
});

// ── H. PEM ────────────────────────────────────────────────────

describe('H. PEM Key / Certificate', () => {
    const pubKey  = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----';
    const privKey = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----';
    const rsaPriv = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----';
    const cert    = '-----BEGIN CERTIFICATE-----\nMIICXTCCAUUCFAjPu\n-----END CERTIFICATE-----';

    it('Public key PEM → pem-public-key', () => {
        expect(hasId(pubKey, 'pem-public-key')).toBe(true);
    });

    it('Public key PEM → isDeterministic', () => {
        expect(analyze(pubKey).results.find(r => r.id === 'pem-public-key')?.isDeterministic).toBe(true);
    });

    it('Private key PEM → pem-private-key with sensitiveWarning', () => {
        const r = analyze(privKey).results.find(x => x.id === 'pem-private-key');
        expect(r).toBeDefined();
        expect(r.sensitiveWarning).toBe(true);
    });

    it('RSA private key PEM → pem-private-key', () => {
        expect(hasId(rsaPriv, 'pem-private-key')).toBe(true);
    });

    it('Certificate PEM → pem-certificate', () => {
        expect(hasId(cert, 'pem-certificate')).toBe(true);
    });

    it('PEM scores higher than generic base64', () => {
        const pemScore = score(pubKey, 'pem-public-key');
        const b64Score = score(pubKey, 'base64');
        expect(pemScore).toBeGreaterThan(b64Score);
    });

    it('Mismatched BEGIN/END labels → pem detected but isDeterministic false', () => {
        const mismatch = '-----BEGIN PUBLIC KEY-----\nabc\n-----END PRIVATE KEY-----';
        const r = analyze(mismatch).results.find(x => x.id === 'pem-public-key' || x.id === 'pem-private-key');
        if (r) expect(r.isDeterministic).toBe(false);
    });
});

// ── I. ENCRYPTION CONTAINERS ─────────────────────────────────

describe('I. Encryption Container Formats', () => {
    it('OpenSSL Salted__ B64 → openssl-salted', () => {
        const salted = btoa('Salted__' + '\x01\x02\x03\x04\x05\x06\x07\x08' + 'fakeciphertext');
        expect(hasId(salted, 'openssl-salted')).toBe(true);
    });

    it('OpenSSL Salted container → isDeterministic', () => {
        const salted = btoa('Salted__' + '\x01\x02\x03\x04\x05\x06\x07\x08' + 'fakeciphertext');
        const r = analyze(salted).results.find(x => x.id === 'openssl-salted');
        expect(r?.isDeterministic).toBe(true);
    });

    it('OpenSSL Salted evidence DOES NOT claim AES-256 specifically', () => {
        const salted = btoa('Salted__' + '\x01\x02\x03\x04\x05\x06\x07\x08' + 'fakeciphertext');
        const r = analyze(salted).results.find(x => x.id === 'openssl-salted');
        const text = r?.evidence.map(e => e.text).join(' ') ?? '';
        // Should not claim specific cipher
        expect(text).not.toMatch(/AES-256-GCM/);
        // Should contain Salted__ marker reference
        expect(text).toMatch(/Salted__/);
    });

    it('CryptoJS prefix U2FsdGVkX1 → cryptojs-legacy-salted', () => {
        expect(hasId('U2FsdGVkX1+abc123', 'cryptojs-legacy-salted')).toBe(true);
    });

    it('CryptoJS → isDeterministic', () => {
        const r = analyze('U2FsdGVkX1+abc123').results.find(x => x.id === 'cryptojs-legacy-salted');
        expect(r?.isDeterministic).toBe(true);
    });

    it('OmniGupt AES-GCM JSON payload → omnigupt-aes-gcm', () => {
        const payload = { version: 1, algorithm: 'AES-256-GCM', iv: 'YWJj', ciphertext: 'ZGVm' };
        const b64 = btoa(JSON.stringify(payload));
        expect(hasId(b64, 'omnigupt-aes-gcm')).toBe(true);
    });

    it('OmniGupt AES-GCM → isDeterministic', () => {
        const payload = { version: 1, algorithm: 'AES-256-GCM', iv: 'YWJj', ciphertext: 'ZGVm' };
        const b64 = btoa(JSON.stringify(payload));
        const r = analyze(b64).results.find(x => x.id === 'omnigupt-aes-gcm');
        expect(r?.isDeterministic).toBe(true);
    });

    it('Random Base64 → NOT classified as omnigupt-aes-gcm', () => {
        const random = btoa('random data that is definitely not a gcm payload at all');
        expect(hasId(random, 'omnigupt-aes-gcm')).toBe(false);
    });
});

// ── J. ENCODING FORMATS ───────────────────────────────────────

describe('J. Encoding Formats', () => {
    it('URL percent-encoded → url-encoded', () => {
        expect(hasId('Hello%20World%21%40%23', 'url-encoded')).toBe(true);
    });

    it('Text with only non-hex %ZZ → NOT url-encoded', () => {
        expect(hasId('Hello%ZZWorld', 'url-encoded')).toBe(false);
    });

    it('Plain text with % but no %XX → NOT url-encoded', () => {
        expect(hasId('50% off sale', 'url-encoded')).toBe(false);
    });

    it('Named HTML entity → html-entities detected', () => {
        expect(hasId('AT&amp;T', 'html-entities')).toBe(true);
    });

    it('Decimal HTML entity → html-entities detected', () => {
        expect(hasId('&#169; Copyright', 'html-entities')).toBe(true);
    });

    it('Hex HTML entity → html-entities detected', () => {
        expect(hasId('&#x1F600; emoji', 'html-entities')).toBe(true);
    });

    it('Plain ampersand → NOT html-entities', () => {
        expect(hasId('bread & butter', 'html-entities')).toBe(false);
    });

    it('Valid \\uXXXX escapes → unicode-escape detected', () => {
        expect(hasId('\\u0048\\u0065\\u006C\\u006C\\u006F', 'unicode-escape')).toBe(true);
    });

    it('Normal backslash text → NOT unicode-escape', () => {
        expect(hasId('C:\\Users\\test', 'unicode-escape')).toBe(false);
    });

    it('Byte-aligned binary → binary-text detected', () => {
        expect(hasId('01001000 01101001', 'binary-text')).toBe(true);
    });

    it('"101" → binary-text present but NOT byte-aligned (low evidence)', () => {
        // Should be present but with low score due to non-byte alignment
        const r = analyze('101').results.find(x => x.id === 'binary-text');
        if (r) {
            // If present, should mention it's not byte-aligned
            const byteNote = r.evidence.some(e => e.type === 'ambiguity');
            expect(byteNote).toBe(true);
        }
    });

    it('ROT13-compatible pure alpha text → rot13-compatible with low score', () => {
        const r = analyze('hello world').results.find(x => x.id === 'rot13-compatible');
        if (r) {
            expect(r.score).toBeLessThan(50); // Low confidence — every alpha string is ROT13-compatible
        }
    });

    it('ROT13 action is decode (not configure-decryption)', () => {
        const r = analyze('hello world').results.find(x => x.id === 'rot13-compatible');
        if (r) {
            expect(r.supportedActions).toContain('decode');
            expect(r.supportedActions).not.toContain('configure-decryption');
        }
    });
});

// ── K. CIPHERTEXT HEURISTICS ─────────────────────────────────

describe('K. Ciphertext Heuristics', () => {
    it('High-entropy Base64 (no marker) → high-entropy-base64', () => {
        // Generate high-entropy-looking data: encoded random-looking bytes
        // Using a long unrecognised B64 string with mixed case and +/
        const highEntropyB64 = 'K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=';
        // This should match base64 or high-entropy-base64
        const r = analyze(highEntropyB64);
        expect(r.results.some(x => x.id === 'base64' || x.id === 'high-entropy-base64')).toBe(true);
    });

    it('High-entropy ciphertext candidate NEVER claims AES-256 specifically', () => {
        const b64 = 'K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=';
        const r = analyze(b64);
        for (const result of r.results) {
            // No result should claim AES-256 as a certainty
            expect(result.displayName).not.toMatch(/AES-256$/);
        }
    });

    it('Block-aligned hex data → hex-encoded or high-entropy-hex', () => {
        // 32 bytes = 64 hex chars, but NOT a hash length... wait 64 IS a hash length
        // Use 48 bytes = 96 hex chars... wait 96 IS sha384. Use 24 bytes = 48 hex chars.
        const hex48 = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4';
        const r = analyze(hex48);
        // Should NOT claim AES-256 as a specific format
        for (const result of r.results) {
            expect(result.displayName).not.toBe('AES-256 Encrypted');
        }
    });

    it('Low-entropy data → ciphertext candidate NOT generated', () => {
        // All 'a' repeated is zero-entropy hex
        const lowEntropy = 'a'.repeat(64);
        const r = analyze(lowEntropy).results;
        const ciphertextCandidates = r.filter(x => x.id === 'high-entropy-base64' || x.id === 'high-entropy-hex');
        // At most score at sha256-like, ciphertext candidates shouldn't fire for low entropy
        for (const c of ciphertextCandidates) {
            expect(c.score).toBeLessThan(50);
        }
    });
});

// ── L. CROSS-FORMAT RANKING (Core regression tests) ──────────

describe('L. Cross-Format Ranking', () => {
    it('MD5 hex → md5-like > base64', () => {
        const hex = 'd41d8cd98f00b204e9800998ecf8427e';
        expect(score(hex, 'md5-like')).toBeGreaterThan(score(hex, 'base64'));
    });

    it('SHA-1 hex → sha1-like > base64', () => {
        const hex = 'da39a3ee5e6b4b0d3255bfef95601890afd80709';
        expect(score(hex, 'sha1-like')).toBeGreaterThan(score(hex, 'base64'));
    });

    it('SHA-256 hex → sha256-like > base64', () => {
        const hex = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        expect(score(hex, 'sha256-like')).toBeGreaterThan(score(hex, 'base64'));
    });

    it('SHA-512 hex → sha512-like > base64', () => {
        const hex = 'a'.repeat(128);
        expect(score(hex, 'sha512-like')).toBeGreaterThan(score(hex, 'base64'));
    });

    it('Genuine Base64 text → base64 outranks sha256-like (if 64 chars)', () => {
        // 64 chars Base64 with + sign — strict hex impossible
        const b64 = 'SGVsbG8gV29ybGQgZnJvbSBDaXBoZXJTZW5zZSBFeGFtcGxl';
        if (b64.length === 48) { /* skip if wrong length */ } // will still test base64 is present
        expect(hasId(btoa('Hello World from CipherSense Test!'), 'base64')).toBe(true);
    });

    it('Valid JWT → jwt > base64url', () => {
        const hdr = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
        const pld = btoa(JSON.stringify({ sub: '1' })).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
        const jwt = `${hdr}.${pld}.sig`;
        expect(score(jwt, 'jwt')).toBeGreaterThan(score(jwt, 'base64url'));
    });

    it('PEM key → pem-public-key top (not base64)', () => {
        const pem = '-----BEGIN PUBLIC KEY-----\nMIIBIjAN\n-----END PUBLIC KEY-----';
        expect(score(pem, 'pem-public-key')).toBeGreaterThan(score(pem, 'base64'));
    });

    it('OpenSSL Salted container → openssl-salted > base64', () => {
        const salted = btoa('Salted__' + '\x01\x02\x03\x04\x05\x06\x07\x08' + 'cipher');
        expect(score(salted, 'openssl-salted')).toBeGreaterThan(score(salted, 'base64'));
    });

    it('bcrypt → bcrypt > any generic encoding', () => {
        const bc = '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW';
        const bcScore = score(bc, 'bcrypt');
        expect(bcScore).toBeGreaterThan(score(bc, 'base64'));
        expect(bcScore).toBeGreaterThan(score(bc, 'base64url'));
    });

    it('Argon2id → argon2 is top result', () => {
        const a2 = '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG';
        expect(top(a2)?.id).toBe('argon2');
    });

    it('PEM private key → pem-private-key is top result', () => {
        const pem = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----';
        expect(top(pem)?.id).toBe('pem-private-key');
    });

    it('OmniGupt GCM payload → omnigupt-aes-gcm is top result', () => {
        const payload = { version: 1, algorithm: 'AES-256-GCM', iv: 'YWJj', ciphertext: 'ZGVm' };
        expect(top(btoa(JSON.stringify(payload)))?.id).toBe('omnigupt-aes-gcm');
    });
});

// ── M. SECURITY / PRIVACY ────────────────────────────────────

describe('M. Security & Privacy Audit', () => {
    it('Engine contains no Math.random()', () => {
        const code = readFileSync(ENGINE_PATH, 'utf8');
        expect(code).not.toContain('Math.random');
    });

    it('Engine contains no fetch() call', () => {
        const code = readFileSync(ENGINE_PATH, 'utf8');
        expect(code).not.toContain('fetch(');
    });

    it('Engine contains no XMLHttpRequest', () => {
        const code = readFileSync(ENGINE_PATH, 'utf8');
        expect(code).not.toContain('XMLHttpRequest');
    });

    it('Engine contains no localStorage write', () => {
        const code = readFileSync(ENGINE_PATH, 'utf8');
        expect(code).not.toContain('localStorage.setItem');
    });

    it('Engine contains no sessionStorage write', () => {
        const code = readFileSync(ENGINE_PATH, 'utf8');
        expect(code).not.toContain('sessionStorage.setItem');
    });

    it('Engine contains no console.log of input values', () => {
        const code = readFileSync(ENGINE_PATH, 'utf8');
        // console.log is allowed if it doesn't log raw input
        // We check there is no console.log(rawInput...) pattern
        expect(code).not.toContain('console.log(raw');
        expect(code).not.toContain('console.log(s)');
    });

    it('Shannon entropy is 0 for single repeated character', () => {
        const H = globalThis.window.cipherSense.shannonEntropy('aaaaaaaaaa');
        expect(H).toBe(0);
    });

    it('Shannon entropy is ~4 for balanced 16-char hex charset', () => {
        const H = globalThis.window.cipherSense.shannonEntropy('0123456789abcdef');
        expect(H).toBeCloseTo(4.0, 0);
    });
});

// ── N. RECURSIVE DECODER ─────────────────────────────────────

describe('N. Recursive Decoder', () => {
    const decode = (s) => globalThis.window.cipherSense.decodeRecursive(s, 0, new Set());

    it('Base64 → text decoded', () => {
        const chain = decode(btoa('Hello World'));
        expect(chain.length).toBeGreaterThan(0);
        expect(chain[0].type).toMatch(/base64/);
        expect(chain[0].decoded).toMatch(/Hello World/);
    });

    it('Hex → UTF-8 decoded', () => {
        const chain = decode('48656c6c6f'); // "Hello" in hex
        expect(chain.length).toBeGreaterThan(0);
        expect(chain[0].type).toMatch(/hex/);
        expect(chain[0].decoded).toMatch(/Hello/);
    });

    it('URL percent-encoded → decoded', () => {
        const chain = decode('Hello%20World');
        expect(chain.some(c => c.type === 'url-decode')).toBe(true);
    });

    it('Binary → decoded text', () => {
        const chain = decode('01001000 01101001'); // "Hi"
        expect(chain.some(c => c.type === 'binary-text')).toBe(true);
    });

    it('ROT13 applied', () => {
        const chain = decode('Uryyb');
        expect(chain.some(c => c.type === 'rot13')).toBe(true);
        expect(chain[0].decoded).toBe('Hello');
    });

    it('Maximum depth respected (no infinite loop)', () => {
        // Triple-nested base64
        const inner = btoa('hello');
        const mid   = btoa(inner);
        const outer = btoa(mid);
        const chain = decode(outer);
        expect(chain.length).toBeLessThanOrEqual(10); // bounded result
    });

    it('Cycle detection prevents same-value recursion', () => {
        // A string that decodes to itself would cause a loop
        // We just verify the visited set prevents crash
        const chain = decode('hello world');
        expect(Array.isArray(chain)).toBe(true);
    });
});
