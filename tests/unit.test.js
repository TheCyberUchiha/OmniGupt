import { describe, it, expect } from 'vitest';

describe('OmniGupt Unit Tests', () => {
  it('should convert strings to UTF-8 bytes and back', () => {
    const original = 'Hello OmniGupt! 🔒';
    const bytes = globalThis.strToBytes(original);
    expect(bytes).toBeDefined();
    expect(bytes.constructor.name).toBe('Uint8Array');
    const roundTrip = globalThis.bytesToStr(bytes);
    expect(roundTrip).toBe(original);
  });

  it('should encode and decode Base64 correctly', () => {
    const originalBytes = new Uint8Array([72, 101, 108, 108, 111]); // 'Hello'
    const b64 = globalThis.bytesToBase64(originalBytes);
    expect(b64).toBe('SGVsbG8=');
    const decodedBytes = globalThis.base64ToBytes(b64);
    expect(Array.from(decodedBytes)).toEqual(Array.from(originalBytes));
  });

  it('should parse Hex strings to bytes correctly', () => {
    const hex = '00 ff 88 a2';
    const bytes = globalThis.hexToBytes(hex);
    expect(Array.from(bytes)).toEqual([0, 255, 136, 162]);
  });

  it('should detect GCM payloads successfully', () => {
    const validPayload = globalThis.bytesToBase64(globalThis.strToBytes(JSON.stringify({
      version: 1,
      algorithm: 'AES-256-GCM',
      iv: 'iv_value',
      ciphertext: 'cipher_value'
    })));
    expect(globalThis.isGcmPayload(validPayload)).toBe(true);

    const invalidPayload = globalThis.bytesToBase64(globalThis.strToBytes('{"version":1}'));
    expect(globalThis.isGcmPayload(invalidPayload)).toBe(false);
    expect(globalThis.isGcmPayload('NotBase64!!')).toBe(false);
  });

  it('should count set bits in a byte correctly (Brian Kernighan\'s)', () => {
    expect(globalThis.countSetBits(0x00)).toBe(0);
    expect(globalThis.countSetBits(0x01)).toBe(1);
    expect(globalThis.countSetBits(0x03)).toBe(2);
    expect(globalThis.countSetBits(0x0f)).toBe(4);
    expect(globalThis.countSetBits(0xff)).toBe(8);
  });

  it('should calculate bit-level Hamming distance for known vectors', () => {
    // 0x00 and 0x00 -> 0 bits changed
    const resIdentical = globalThis.calculateHammingDistance(new Uint8Array([0x00]), new Uint8Array([0x00]));
    expect(resIdentical.changedBits).toBe(0);
    expect(resIdentical.bitPercentage).toBe(0);

    // 0x00 and 0xff -> 8 bits changed
    const resOpposite = globalThis.calculateHammingDistance(new Uint8Array([0x00]), new Uint8Array([0xff]));
    expect(resOpposite.changedBits).toBe(8);
    expect(resOpposite.bitPercentage).toBe(100);

    // 0x0f and 0xf0 -> 8 bits changed
    const resShift = globalThis.calculateHammingDistance(new Uint8Array([0x0f]), new Uint8Array([0xf0]));
    expect(resShift.changedBits).toBe(8);
    expect(resShift.bitPercentage).toBe(100);

    // 0x55 and 0xaa (01010101 vs 10101010) -> 8 bits changed
    const resAlternating = globalThis.calculateHammingDistance(new Uint8Array([0x55]), new Uint8Array([0xaa]));
    expect(resAlternating.changedBits).toBe(8);
  });

  it('should validate audit records matching the allowed schema', () => {
    const validRecord = {
      id: '8d2a6a16-64cc-4df5-a7b2-04e84b8d7ef2',
      timestamp: new Date().toISOString(),
      algorithm: 'AES-GCM',
      classification: 'MODERN / RECOMMENDED - RECOMMENDED',
      type: 'encrypt',
      inputSize: 10,
      outputSize: 128,
      status: 'success',
      keyMode: 'Generated Key'
    };
    expect(globalThis.validateAuditRecord(validRecord)).toBe(true);

    // Reject record with extra unknown fields
    const recordWithExtra = { ...validRecord, plaintext: 'Transfer 500' };
    expect(globalThis.validateAuditRecord(recordWithExtra)).toBe(false);

    // Reject record with invalid status
    const recordWithInvalidStatus = { ...validRecord, status: 'malicious' };
    expect(globalThis.validateAuditRecord(recordWithInvalidStatus)).toBe(false);
  });
});
