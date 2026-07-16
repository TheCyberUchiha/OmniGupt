# OmniGupt: Browser-Based Cryptography & Encryption Toolkit

OmniGupt is a premium, client-side browser cryptography and encryption/decryption toolkit. It provides a clean, responsive, and glassmorphic user interface to perform secure cryptographic calculations and key generation directly in the web browser.

---

## Key Features

1. **Modern Authenticated Encryption**: 
   * **AES-256-GCM** (marked as **RECOMMENDED**) using the native browser Web Crypto API.
   * Generates unique 96-bit random IVs independently for every encryption operation.
   * Leverages 128-bit authentication tags to verify ciphertext integrity and prevent active tampering.
2. **Key Derivation (PBKDF2)**:
   * Password-based key derivation using standard Web Crypto PBKDF2.
   * Generates a unique 16-byte random salt for every passphrase encryption.
   * Processes keys with SHA-256 and an OWASP-compliant `600,000` iteration count.
3. **CSPRNG Key Generation**:
   * True random passphrase and hex key generation utilizing the browser's native cryptographically secure random number generator (`window.crypto.getRandomValues()`).
4. **Legacy Compatibility**:
   * Preserves backward compatibility for legacy ciphers: AES-CBC (Legacy CBC), DES, Triple DES (3DES), and Rabbit ciphers.
   * Integrates an auto-detection parser to automatically identify versioned GCM payloads or legacy Base64 formats upon pasting.
5. **Secure Storage Policy**:
   * Never persists raw plaintexts, encryption keys, or passphrases. Secrets are processed purely in-memory and discarded upon page reload.
   * Logs only safe, audited metadata (Algorithm, Operation, Status, Payload Size, Timestamp) to client downloads and backend databases.
7. **Security Lab**:
   * **Tamper Detection Lab**: Allows users to interactively encrypt plaintexts, modify exactly one byte of GCM ciphertext, and witness tag authentication failure in the Web Crypto API.
   * **Avalanche Effect Visualizer**: Interactively modifies a single character of input text and compares ciphertext differences at the bit level using Hamming distance calculations.

---

## Supported Cryptographic Tiers

OmniGupt separates secure, modern authenticated ciphers from legacy ciphers using distinct visual banners and screen-reader accessible badges in the selector:

* **MODERN / RECOMMENDED**:
  * **AES-256-GCM**: AEAD mode providing authenticated confidentiality and integrity protection.
* **LEGACY COMPATIBILITY**:
  * **AES (Legacy CBC)**: Block cipher chaining providing confidentiality only.
* **LEGACY / EDUCATIONAL**:
  * **DES**: Broken cipher (56-bit effective key length). Retained for retro-compatibility and education.
  * **Triple DES (3DES)**: Deprecated block cipher vulnerable to Sweet32 collision attacks.
  * **Rabbit**: Obsolete, non-standardized stream cipher.

---

## Security Lab Modules

OmniGupt includes a client-side **Security Lab** containing:
1. **Tamper Detection Lab**: Designed to visually demonstrate the security advantages of Authenticated Encryption (AES-GCM) over legacy unauthenticated algorithms by modifying exactly one ciphertext byte.
2. **Avalanche Effect Visualizer**: Illustrates the avalanche property by measuring the exact bit-level Hamming distance difference between two outputs when only one input character changes.

---

## Getting Started

### Local Setup & Static Execution
OmniGupt can be executed statically directly from the filesystem (works on `file://` protocol):
1. Simply double-click [index.html](file:///c:/Users/91799/OneDrive/Desktop/Darshak/OmniGupt-main/index.html) to open the interface in any modern browser.

### Local Logging Server (Optional)
If database logging is desired:
1. Ensure Python is installed.
2. Install Flask dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the Flask server:
   ```bash
   python server.py
   ```
4. The server will start on `http://localhost:5000/`. OmniGupt will auto-detect the backend and securely log safe operation metadata to the SQLite database.
5. View logged audit statistics by opening [history.html](file:///c:/Users/91799/OneDrive/Desktop/Darshak/OmniGupt-main/history.html).

---

## Cryptographic and Security Policies
For detailed specifications of the cryptography implementations and legacy standards, please read:
* [AES_GCM_IMPLEMENTATION.md](file:///c:/Users/91799/OneDrive/Desktop/Darshak/OmniGupt-main/AES_GCM_IMPLEMENTATION.md)
* [LEGACY_CRYPTO_POLICY.md](file:///c:/Users/91799/OneDrive/Desktop/Darshak/OmniGupt-main/LEGACY_CRYPTO_POLICY.md)
* [SECURITY_FIXES.md](file:///c:/Users/91799/OneDrive/Desktop/Darshak/OmniGupt-main/SECURITY_FIXES.md)
* [TAMPER_DETECTION_LAB.md](file:///c:/Users/91799/OneDrive/Desktop/Darshak/OmniGupt-main/TAMPER_DETECTION_LAB.md)
* [AVALANCHE_EFFECT_LAB.md](file:///c:/Users/91799/OneDrive/Desktop/Darshak/OmniGupt-main/AVALANCHE_EFFECT_LAB.md)
* [SECURE_AUDIT_HISTORY.md](file:///c:/Users/91799/OneDrive/Desktop/Darshak/OmniGupt-main/SECURE_AUDIT_HISTORY.md)
* [UI_UX_UPGRADE.md](file:///c:/Users/91799/OneDrive/Desktop/Darshak/OmniGupt-main/UI_UX_UPGRADE.md)
