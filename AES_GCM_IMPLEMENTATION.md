# OmniGupt AES-256-GCM Cryptographic Implementation Specifications

This document outlines the cryptographic specifications, key derivation details, and serialization payload formats adopted for the modern authenticated encryption mode (**AES-256-GCM**) in OmniGupt.

---

## 1. Cryptographic Design Decisions

### Why IV Uniqueness Matters
Under AES-GCM (Galois/Counter Mode), repeating an Initialization Vector (IV) with the same encryption key breaks security completely. Known as a "nonce reuse" vulnerability, it allows an observer to recover the authentication key (GHASH key) and decrypt all other messages sharing the same key-IV combination.
* **OmniGupt Fix**: A fresh, high-entropy 96-bit (12-byte) IV is generated using the browser's cryptographically secure random number generator (`window.crypto.getRandomValues()`) for every encryption operation.

### Why AES-GCM Provides Integrity
Unlike legacy modes like AES-CBC (which only provides confidentiality), AES-GCM is an **Authenticated Encryption with Associated Data (AEAD)** algorithm. In addition to encrypting the plaintext, GCM computes a 128-bit authentication tag. During decryption, the tag is validated to ensure that:
* The ciphertext has not been modified or corrupted.
* The IV has not been altered.
* The key is correct.
If any single bit of the ciphertext, IV, or header is modified, decryption immediately fails, preventing active padding oracle, bit-flipping, or manipulation attacks.

### Why the IV and Salt Are Not Secret
* **IV**: The IV's role is to introduce variation so that identical plaintexts result in unique ciphertexts. It is not a secret key and is safely stored in cleartext alongside the ciphertext in the payload.
* **Salt**: The salt prevents pre-computed dictionary attacks (like rainbow table lookups) by ensuring that two users with the exact same passphrase derive completely different keys. Like the IV, the salt is public metadata required to perform the key derivation steps during decryption and does not need to be hidden.

### Memory-Only Secret Storage Policy
Passphrases, raw keys, and plaintexts are processed in-memory only inside volatile JavaScript execution contexts. Persisting them to disk (in browser storage like `localStorage` or server databases) exposes them to compromise by local malware, unauthorized users, or data leakage. Secrets are immediately discarded from memory once the cryptographic operations are completed or when the page is reloaded.

---

## 2. Key Derivation (PBKDF2)

When a string passphrase is used, it is converted to a 256-bit AES key using PBKDF2 (Password-Based Key Derivation Function 2) with the following parameters:
* **Hash function**: `SHA-256`
* **Iteration count**: `600,000` iterations (aligned with modern OWASP standards)
* **Salt**: 16 bytes (128 bits) of CSPRNG-generated randomness per encryption
* **Key length**: 256 bits (32 bytes)

---

## 3. Versioned Payload Serialization Formats

The final output displayed to the user is a single Base64-encoded string representing a versioned JSON object. This ensures ease of copy-pasting and clean parsing during decryption.

### Mode 1: Raw/Generated 256-bit Key
When a raw 256-bit Hex key is used, no key derivation is performed. The JSON payload before Base64 encoding has the following structure:

```json
{
  "version": 1,
  "algorithm": "AES-256-GCM",
  "iv": "dGVzdF9pdl9iYXNlNjQ=",
  "ciphertext": "Y2lwaGVydGV4dF9iYXNlNjQ="
}
```

* `version`: Schema version (integer, currently `1`).
* `algorithm`: Encryption algorithm string (strictly `"AES-256-GCM"`).
* `iv`: Base64-encoded 96-bit (12-byte) initialization vector.
* `ciphertext`: Base64-encoded ciphertext combined with the 128-bit authentication tag appended at the end (standard Web Crypto array output).

---

### Mode 2: Passphrase Mode (PBKDF2 Derived)
When a passphrase is used, the JSON payload includes KDF metadata required to derive the key:

```json
{
  "version": 1,
  "algorithm": "AES-256-GCM",
  "kdf": "PBKDF2",
  "hash": "SHA-256",
  "iterations": 600000,
  "salt": "c2FsdF9iYXNlNjQ=",
  "iv": "dGVzdF9pdl9iYXNlNjQ=",
  "ciphertext": "Y2lwaGVydGV4dF9iYXNlNjQ="
}
```

* `kdf`: Key derivation function used (strictly `"PBKDF2"`).
* `hash`: Hash function used for derivation (strictly `"SHA-256"`).
* `iterations`: Iteration count parameter (strictly `600000`).
* `salt`: Base64-encoded 128-bit (16-byte) random salt.

---

## 4. Verification and Error Handling

During decryption, the base64 payload is parsed back to JSON. The following parameters are verified:
1. The `version` must be `1`.
2. The `algorithm` must be `"AES-256-GCM"`.
3. If KDF metadata is present, a 256-bit key is derived using the parameters and the user-supplied passphrase.
4. The Web Crypto `subtle.decrypt` API decrypts and verifies the ciphertext tag.
5. If tag validation or parameters check fails, the generic error message is returned:
   `"Authentication failed. The encrypted data may have been modified or the key is incorrect."`
