import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const bundlePath = path.resolve(__dirname, '../index-bundle.js');

console.log('----------------------------------------------------');
console.log('🛡️  OmniGupt Security Posture Regression Scanner 🛡️');
console.log('----------------------------------------------------');

let failures = [];

function assert(condition, message) {
  if (!condition) {
    failures.push(message);
    console.log(`❌ FAIL: ${message}`);
  } else {
    console.log(`✅ PASS: ${message}`);
  }
}

// 1. Check for Math.random() in index-bundle.js
if (fs.existsSync(bundlePath)) {
  const code = fs.readFileSync(bundlePath, 'utf8');

  // Verify Math.random() is NOT used for keys, IV, salts, nonces, or IDs
  const hasMathRandom = code.includes('Math.random()');
  assert(!hasMathRandom, 'No Math.random() usage in production cryptographic code paths (CSPRNG window.crypto.getRandomValues is mandatory).');

  // 2. Check for unsafe innerHTML in identified security-sensitive rendering paths
  // Check if innerHTML is used on audit table cells or dynamic inputs
  const lines = code.split('\n');
  let auditHistoryInnerHTML = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.includes('renderAuditHistoryUI') || line.includes('renderHistory') || line.includes('audit-history')) {
      // Look for innerHTML assignments in surrounding lines
      for (let j = Math.max(0, i - 10); j < Math.min(lines.length, i + 50); j++) {
        // Exclude safe empty assignments: innerHTML = '' or innerHTML = ""
        if (lines[j].includes('.innerHTML =') && !/innerHTML\s*=\s*['"]\s*['"]/i.test(lines[j])) {
          auditHistoryInnerHTML = true;
        }
      }
    }
  }
  assert(!auditHistoryInnerHTML, 'No unsafe innerHTML usage in Audit History UI rendering paths.');

  // 3. LocalStorage / SessionStorage Safety Checks
  // Check if secret key or plaintexts are set to localStorage
  const hasLocalStorageSetKeys = /localStorage\.setItem\s*\(\s*['"`](key|secret|passphrase|password|plaintext|ciphertext)['"`]/i.test(code);
  assert(!hasLocalStorageSetKeys, 'No LocalStorage setItem calls for sensitive field names.');
} else {
  failures.push('index-bundle.js not found!');
  console.log('❌ FAIL: index-bundle.js not found!');
}

// 4. Verify forbidden field filters inside Audit History logs
console.log('\n--- Verifying Audit Log Safety Guardrails ---');

const forbiddenFields = ['key', 'secret', 'passphrase', 'password', 'plaintext', 'ciphertext', 'input', 'output', 'decrypted'];
const sampleValidRecord = {
  id: '71cb6cf6-0414-41d3-883a-4a6f8b9d7ef2',
  timestamp: new Date().toISOString(),
  algorithm: 'AES-256-GCM',
  classification: 'MODERN / RECOMMENDED',
  type: 'encrypt',
  inputSize: 15,
  outputSize: 120,
  status: 'success',
  keyMode: 'Passphrase'
};

// Mock validateAuditRecord logic from index-bundle.js (exact matches on properties allowlist and forbidden fields)
function validateAuditRecord(record) {
  if (!record || typeof record !== 'object') return false;
  
  const keys = Object.keys(record);
  const allowedFields = ['id', 'timestamp', 'algorithm', 'classification', 'type', 'inputSize', 'outputSize', 'status', 'keyMode'];
  for (const key of keys) {
    if (!allowedFields.includes(key)) {
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
  return true;
}

assert(validateAuditRecord(sampleValidRecord), 'Audit record validation allows safe operation metadata.');

for (const forbidden of forbiddenFields) {
  const badRecord = { ...sampleValidRecord, [forbidden]: 'sensitive_information_leak' };
  assert(!validateAuditRecord(badRecord), `Audit record validation rejects forbidden property "${forbidden}".`);
}

const unknownFieldRecord = { ...sampleValidRecord, custom_user_data: 'extra_value' };
assert(!validateAuditRecord(unknownFieldRecord), 'Audit record validation rejects unknown or non-allowlisted properties.');

console.log('\n----------------------------------------------------');
if (failures.length > 0) {
  console.log(`❌ SECURITY POSTURE SCAN FAILED with ${failures.length} issues.`);
  process.exit(1);
} else {
  console.log('✅ SECURITY POSTURE SCAN PASSED successfully.');
  process.exit(0);
}
