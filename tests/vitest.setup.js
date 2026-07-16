import fs from 'fs';
import path from 'path';
import CryptoJS from 'crypto-js';
import { vi } from 'vitest';

// Load CryptoJS onto global context
globalThis.CryptoJS = CryptoJS;
if (globalThis.window) {
  globalThis.window.CryptoJS = CryptoJS;
  // Ensure native Web Crypto API is mapped to JSDOM window
  if (!globalThis.window.crypto) {
    globalThis.window.crypto = globalThis.crypto;
  }
}

// Mock fetch requests to prevent tests from hitting actual loopback servers
globalThis.fetch = vi.fn().mockImplementation(() => Promise.resolve({
  ok: false,
  status: 404,
  json: () => Promise.resolve([])
}));

// Load index.html HTML markup into the global JSDOM document
const htmlPath = path.resolve(__dirname, '../index.html');
const html = fs.readFileSync(htmlPath, 'utf8');
document.documentElement.innerHTML = html;

// Now execute index-bundle.js to initialize DOM events, variables, and ciphers
const bundlePath = path.resolve(__dirname, '../index-bundle.js');
const bundleCode = fs.readFileSync(bundlePath, 'utf8');

// Append helper bindings to expose top-level declarations onto globalThis
const exposeSnippet = `
globalThis.strToBytes = strToBytes;
globalThis.bytesToStr = bytesToStr;
globalThis.bytesToBase64 = bytesToBase64;
globalThis.base64ToBytes = base64ToBytes;
globalThis.hexToBytes = hexToBytes;
globalThis.isGcmPayload = isGcmPayload;
globalThis.encryptGCM = encryptGCM;
globalThis.decryptGCM = decryptGCM;
globalThis.cryptoEncrypt = cryptoEncrypt;
globalThis.cryptoDecrypt = cryptoDecrypt;
globalThis.checkKeyStrength = checkKeyStrength;
globalThis.validateAuditRecord = validateAuditRecord;
globalThis.countSetBits = countSetBits;
globalThis.calculateHammingDistance = calculateHammingDistance;
`;

// Evaluate the bundle code in the global context
const runBundle = new Function(bundleCode + '\n' + exposeSnippet);
runBundle();

// Fire DOMContentLoaded so that DOM event listeners attach
const event = new Event('DOMContentLoaded', {
  bubbles: true,
  cancelable: true
});
document.dispatchEvent(event);
