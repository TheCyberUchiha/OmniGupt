import { describe, it, expect } from 'vitest';

describe('OmniGupt Cryptographic Modules', () => {
  const samplePlaintext = 'Secure OmniGupt Plaintext Message';
  const samplePassphrase = 'MyExtremelySecurePassphrase123!';
  const rawHexKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

  describe('AES-256-GCM Implementation', () => {
    it('should encrypt and decrypt a round trip correctly using a passphrase', async () => {
      const encrypted = await globalThis.cryptoEncrypt('AES-GCM', samplePlaintext, samplePassphrase, false);
      expect(typeof encrypted).toBe('string');
      expect(encrypted.length).toBeGreaterThan(0);

      const decrypted = await globalThis.cryptoDecrypt('AES-GCM', encrypted, samplePassphrase, false);
      expect(decrypted).toBe(samplePlaintext);
    });

    it('should encrypt and decrypt a round trip correctly using a raw hex key', async () => {
      const encrypted = await globalThis.cryptoEncrypt('AES-GCM', samplePlaintext, rawHexKey, true);
      const decrypted = await globalThis.cryptoDecrypt('AES-GCM', encrypted, rawHexKey, true);
      expect(decrypted).toBe(samplePlaintext);
    });

    it('should generate different ciphertexts for the same plaintext and key on consecutive runs', async () => {
      const enc1 = await globalThis.cryptoEncrypt('AES-GCM', samplePlaintext, samplePassphrase, false);
      const enc2 = await globalThis.cryptoEncrypt('AES-GCM', samplePlaintext, samplePassphrase, false);
      expect(enc1).not.toBe(enc2);
    });

    it('should generate a 96-bit (12 bytes) IV', async () => {
      const encrypted = await globalThis.cryptoEncrypt('AES-GCM', samplePlaintext, samplePassphrase, false);
      const payload = JSON.parse(globalThis.bytesToStr(globalThis.base64ToBytes(encrypted)));
      const ivBytes = globalThis.base64ToBytes(payload.iv);
      expect(ivBytes.length).toBe(12); // 12 bytes = 96 bits
    });

    it('should fail authentication if the wrong passphrase/key is provided', async () => {
      const encrypted = await globalThis.cryptoEncrypt('AES-GCM', samplePlaintext, samplePassphrase, false);
      await expect(
        globalThis.cryptoDecrypt('AES-GCM', encrypted, 'WrongPassphrase', false)
      ).rejects.toThrow();
    });

    it('should fail authentication if the ciphertext payload is tampered with', async () => {
      const encrypted = await globalThis.cryptoEncrypt('AES-GCM', samplePlaintext, samplePassphrase, false);
      const payload = JSON.parse(globalThis.bytesToStr(globalThis.base64ToBytes(encrypted)));
      
      // Tamper with the ciphertext by altering the last byte
      const cipherBytes = globalThis.base64ToBytes(payload.ciphertext);
      cipherBytes[cipherBytes.length - 1] ^= 0x01;
      payload.ciphertext = globalThis.bytesToBase64(cipherBytes);
      
      const tamperedPayloadStr = globalThis.bytesToBase64(globalThis.strToBytes(JSON.stringify(payload)));
      await expect(
        globalThis.cryptoDecrypt('AES-GCM', tamperedPayloadStr, samplePassphrase, false)
      ).rejects.toThrow();
    });

    it('should fail authentication if the IV is tampered with', async () => {
      const encrypted = await globalThis.cryptoEncrypt('AES-GCM', samplePlaintext, samplePassphrase, false);
      const payload = JSON.parse(globalThis.bytesToStr(globalThis.base64ToBytes(encrypted)));
      
      // Tamper with the IV by altering the last byte
      const ivBytes = globalThis.base64ToBytes(payload.iv);
      ivBytes[ivBytes.length - 1] ^= 0x01;
      payload.iv = globalThis.bytesToBase64(ivBytes);
      
      const tamperedPayloadStr = globalThis.bytesToBase64(globalThis.strToBytes(JSON.stringify(payload)));
      await expect(
        globalThis.cryptoDecrypt('AES-GCM', tamperedPayloadStr, samplePassphrase, false)
      ).rejects.toThrow();
    });

    it('should fail if payload version is unsupported', async () => {
      const encrypted = await globalThis.cryptoEncrypt('AES-GCM', samplePlaintext, samplePassphrase, false);
      const payload = JSON.parse(globalThis.bytesToStr(globalThis.base64ToBytes(encrypted)));
      payload.version = 999; // Unsupported version
      
      const tamperedPayloadStr = globalThis.bytesToBase64(globalThis.strToBytes(JSON.stringify(payload)));
      await expect(
        globalThis.cryptoDecrypt('AES-GCM', tamperedPayloadStr, samplePassphrase, false)
      ).rejects.toThrow(/version/i);
    });

    it('should fail if algorithm name is incorrect or missing', async () => {
      const encrypted = await globalThis.cryptoEncrypt('AES-GCM', samplePlaintext, samplePassphrase, false);
      const payload = JSON.parse(globalThis.bytesToStr(globalThis.base64ToBytes(encrypted)));
      payload.algorithm = 'AES-GCM-FAKE';
      
      const tamperedPayloadStr = globalThis.bytesToBase64(globalThis.strToBytes(JSON.stringify(payload)));
      await expect(
        globalThis.cryptoDecrypt('AES-GCM', tamperedPayloadStr, samplePassphrase, false)
      ).rejects.toThrow();
    });

    it('should successfully round-trip Unicode, Hindi, Gujarati, and Emojis', async () => {
      const languages = [
        'Unicode: αβγδεζηθικλμνξοπρστυφχψω',
        'Hindi: नमस्ते दुनिया',
        'Gujarati: નમસ્તે વિશ્વ',
        'Emoji: 🔒🔑🚀🛡️🧪📊'
      ];
      for (const input of languages) {
        const encrypted = await globalThis.cryptoEncrypt('AES-GCM', input, samplePassphrase, false);
        const decrypted = await globalThis.cryptoDecrypt('AES-GCM', encrypted, samplePassphrase, false);
        expect(decrypted).toBe(input);
      }
    });

    it('should safely reject empty plaintext input during encryption', async () => {
      await expect(
        globalThis.cryptoEncrypt('AES-GCM', '', samplePassphrase, false)
      ).rejects.toThrow();
    });

    it('should successfully round-trip large text sizes', async () => {
      const largeText = 'A'.repeat(50 * 1024); // 50 KB
      const encrypted = await globalThis.cryptoEncrypt('AES-GCM', largeText, samplePassphrase, false);
      const decrypted = await globalThis.cryptoDecrypt('AES-GCM', encrypted, samplePassphrase, false);
      expect(decrypted).toBe(largeText);
    });
  });

  describe('Passphrase / PBKDF2 Configuration', () => {
    it('should generate a salt and ensure salt differs across runs', async () => {
      const enc1 = await globalThis.cryptoEncrypt('AES-GCM', samplePlaintext, samplePassphrase, false);
      const enc2 = await globalThis.cryptoEncrypt('AES-GCM', samplePlaintext, samplePassphrase, false);

      const payload1 = JSON.parse(globalThis.bytesToStr(globalThis.base64ToBytes(enc1)));
      const payload2 = JSON.parse(globalThis.bytesToStr(globalThis.base64ToBytes(enc2)));

      expect(payload1.salt).toBeDefined();
      expect(payload2.salt).toBeDefined();
      expect(payload1.salt).not.toBe(payload2.salt);
    });

    it('should use PBKDF2 KDF metadata referencing SHA-256 and 600,000 iterations', async () => {
      const encrypted = await globalThis.cryptoEncrypt('AES-GCM', samplePlaintext, samplePassphrase, false);
      const payload = JSON.parse(globalThis.bytesToStr(globalThis.base64ToBytes(encrypted)));
      
      expect(payload.kdf).toBe('PBKDF2');
      expect(payload.hash).toBe('SHA-256');
      expect(payload.iterations).toBe(600000);
    });

    it('should reject or bound extreme or malicious iteration values to prevent resource exhaustion', async () => {
      const encrypted = await globalThis.cryptoEncrypt('AES-GCM', samplePlaintext, samplePassphrase, false);
      const payload = JSON.parse(globalThis.bytesToStr(globalThis.base64ToBytes(encrypted)));

      // Case 1: Maliciously high iterations count (2,000,001+)
      payload.iterations = 5000000;
      let tamperedPayloadStr = globalThis.bytesToBase64(globalThis.strToBytes(JSON.stringify(payload)));
      await expect(
        globalThis.cryptoDecrypt('AES-GCM', tamperedPayloadStr, samplePassphrase, false)
      ).rejects.toThrow(/iteration/i);

      // Case 2: Maliciously small iterations count (under 1000)
      payload.iterations = 999;
      tamperedPayloadStr = globalThis.bytesToBase64(globalThis.strToBytes(JSON.stringify(payload)));
      await expect(
        globalThis.cryptoDecrypt('AES-GCM', tamperedPayloadStr, samplePassphrase, false)
      ).rejects.toThrow(/iteration/i);

      // Case 3: Invalid NaN iteration parameter
      payload.iterations = 'dangerous-abc';
      tamperedPayloadStr = globalThis.bytesToBase64(globalThis.strToBytes(JSON.stringify(payload)));
      await expect(
        globalThis.cryptoDecrypt('AES-GCM', tamperedPayloadStr, samplePassphrase, false)
      ).rejects.toThrow(/iteration/i);
    });

    it('should ensure the passphrase is never included in the JSON payload', async () => {
      const encrypted = await globalThis.cryptoEncrypt('AES-GCM', samplePlaintext, samplePassphrase, false);
      const payloadStr = globalThis.bytesToStr(globalThis.base64ToBytes(encrypted));
      expect(payloadStr.includes(samplePassphrase)).toBe(false);
    });
  });

  describe('Legacy compatibility regression tests', () => {
    // Static test vectors generated with CryptoJS and key "SecurePassphrase123"
    // Plaintext = "OmniGupt Compatibility Vector"
    const key = 'SecurePassphrase123';
    const originalText = 'OmniGupt Compatibility Vector';
    
    const aesCbcVector = 'U2FsdGVkX18LJrbMKqtb5CEu/jVVuR2ZWabG8fbce2POLG/mgcpAMIvX40j9i+/F';
    const desVector = 'U2FsdGVkX1867Sz3549008nSpSq3WgaK5I6FKc1mg/+DAcq34Z2PcTz6w+G3m7Aa';
    const tripleDesVector = 'U2FsdGVkX1/fRIDL+o3mHqYK+2baK11i5WNp9PtGjIGPcBZ/5iDvOiSIWnGyhuYG';
    const rabbitVector = 'U2FsdGVkX18RHLfpmhsrQGFmTpfpMIFjwzr6JdwBloIVIj90VvvRNpmT1rlu';

    it('should correctly decrypt legacy AES-CBC ciphertexts', async () => {
      const result = await globalThis.cryptoDecrypt('AES', aesCbcVector, key, false);
      expect(result).toBe(originalText);
    });

    it('should correctly decrypt legacy DES ciphertexts', async () => {
      const result = await globalThis.cryptoDecrypt('DES', desVector, key, false);
      expect(result).toBe(originalText);
    });

    it('should correctly decrypt legacy Triple DES ciphertexts', async () => {
      const result = await globalThis.cryptoDecrypt('TripleDES', tripleDesVector, key, false);
      expect(result).toBe(originalText);
    });

    it('should correctly decrypt legacy Rabbit ciphertexts', async () => {
      const result = await globalThis.cryptoDecrypt('Rabbit', rabbitVector, key, false);
      expect(result).toBe(originalText);
    });

    it('should run a modern encrypt-decrypt flow for DES, TripleDES, and Rabbit', async () => {
      const algos = ['DES', 'TripleDES', 'Rabbit'];
      for (const algo of algos) {
        const encrypted = await globalThis.cryptoEncrypt(algo, originalText, key, false);
        const decrypted = await globalThis.cryptoDecrypt(algo, encrypted, key, false);
        expect(decrypted).toBe(originalText);
      }
    });
  });
});
