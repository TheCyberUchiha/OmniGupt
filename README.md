<div align="center">

# 🔒 OmniGupt

**Modern, Browser-Based Cryptography & Encryption Analysis Toolkit**

Encrypt, decrypt, and fingerprint cryptographic data — entirely client-side, entirely in your browser.

[![Live Demo](https://img.shields.io/badge/demo-live-brightgreen?style=for-the-badge)](https://omnigupt.vercel.app/)
[![GitHub stars](https://img.shields.io/github/stars/TheCyberUchiha/OmniGupt?style=for-the-badge)](https://github.com/TheCyberUchiha/OmniGupt/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/TheCyberUchiha/OmniGupt?style=for-the-badge)](https://github.com/TheCyberUchiha/OmniGupt/network/members)
[![GitHub last commit](https://img.shields.io/github/last-commit/TheCyberUchiha/OmniGupt?style=for-the-badge)](https://github.com/TheCyberUchiha/OmniGupt/commits/main)

[**🚀 Live App**](https://omnigupt.vercel.app/) · [**🐛 Report Bug**](https://github.com/TheCyberUchiha/OmniGupt/issues) · [**💡 Request Feature**](https://github.com/TheCyberUchiha/OmniGupt/issues)

</div>

---

## 📖 Table of Contents

- [About](#-about)
- [Features](#-features)
- [Supported Cryptographic Tiers](#-supported-cryptographic-tiers)
- [Security Lab](#-security-lab)
- [CipherSense — Format Analyzer](#-ciphersense--format-analyzer)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [Usage](#-usage)
- [Running Tests](#-running-tests)
- [Security & Privacy Model](#-security--privacy-model)
- [Documentation](#-documentation)
- [FAQ](#-faq)
- [Contributing](#-contributing)
- [License](#-license)
- [Disclaimer](#-disclaimer)
- [Acknowledgments](#-acknowledgments)

---

## 📌 About

OmniGupt is a client-side cryptography lab built for students, developers, and security enthusiasts who want to *see* cryptography work instead of just reading about it. It exposes the real parameters most tools hide — key derivation function, iteration counts, IV generation, authentication tags — and pairs them with interactive labs that make abstract crypto properties (like the avalanche effect or authenticated encryption) visible and tangible.

Nothing you type ever leaves your browser unless you explicitly run the optional local logging server yourself — and even then, only non-sensitive metadata is stored.

> 💡 **Add a screenshot or GIF here** — a short demo clip of the Encrypt panel or the Tamper Detection Lab in action goes a long way toward making this README pop. Drop it in an `/assets` folder and reference it like:
> `![OmniGupt demo](./assets/demo.gif)`

## ✨ Features

| | Feature | Description |
|---|---|---|
| 🔐 | **Modern Authenticated Encryption** | AES-256-GCM via the native Web Crypto API, with a fresh random 96-bit IV and a 128-bit auth tag per operation |
| 🔑 | **Password-Based Key Derivation** | PBKDF2-HMAC-SHA256 with a unique 16-byte salt and 600,000 iterations (OWASP-aligned) |
| 🎲 | **CSPRNG Key Generator** | True random passphrase / hex key generation via `window.crypto.getRandomValues()` |
| 🕰️ | **Legacy Cipher Support** | AES-CBC, DES, 3DES, and Rabbit — included for education and retro-compatibility, clearly labeled |
| 🔍 | **Auto-Detect on Decrypt** | Recognizes versioned GCM payloads vs. legacy Base64 formats automatically |
| 🚫 | **No Persisted Secrets** | Plaintext, keys, and passphrases live in memory only — never written to disk or a database |
| 🧪 | **Security Lab** | Interactive Tamper Detection & Avalanche Effect visualizers |
| 🕵️ | **CipherSense** | Paste any unknown value to get a ranked, explainable format analysis |

## 🧩 Supported Cryptographic Tiers

| Tier | Algorithm | Notes |
|---|---|---|
| ✅ Modern / Recommended | **AES-256-GCM** | Authenticated encryption — confidentiality *and* integrity, native Web Crypto API |
| ⚠️ Legacy Compatibility | **AES-CBC** | Confidentiality only, no built-in integrity check |
| ⚠️ Legacy / Educational | **DES** | Broken — 56-bit effective key length |
| ⚠️ Legacy / Educational | **Triple DES (3DES)** | Deprecated, vulnerable to Sweet32 collision attacks |
| ⚠️ Legacy / Educational | **Rabbit** | Obsolete, non-standardized stream cipher |

Legacy ciphers run on [CryptoJS](https://github.com/brix/crypto-js) since the native Web Crypto API doesn't implement them. AES-256-GCM and PBKDF2 use the browser's built-in Web Crypto API directly.

## 🧪 Security Lab

Two hands-on modules that turn abstract crypto theory into something you can watch happen:

- **Tamper Detection Lab** — encrypt a plaintext with AES-GCM, flip a single byte of the ciphertext, and watch authentication fail instantly — a direct, visual reason authenticated encryption beats legacy unauthenticated ciphers.
- **Avalanche Effect Visualizer** — change one character of input and compare the resulting ciphertexts bit-by-bit via Hamming distance, showing how a tiny input change should cascade into a completely different output.

## 🕵️ CipherSense — Format Analyzer

Paste an unknown hash, encoded string, or ciphertext and get a ranked, explainable guess of what it is — useful for CTFs, security triage, or just building intuition for what different crypto output looks like. Runs 100% locally; nothing is transmitted.

## 🛠️ Tech Stack

<div align="center">

![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square&logo=javascript&logoColor=black)
![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=flat-square&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=flat-square&logo=css3&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=flat-square&logo=flask&logoColor=white)
![Vitest](https://img.shields.io/badge/Vitest-6E9F18?style=flat-square&logo=vitest&logoColor=white)
![Playwright](https://img.shields.io/badge/Playwright-2EAD33?style=flat-square&logo=playwright&logoColor=white)

</div>

| Layer | Technology |
|---|---|
| Core crypto | Native **Web Crypto API** (AES-GCM, PBKDF2) |
| Legacy ciphers | **CryptoJS** (AES-CBC, DES, 3DES, Rabbit) |
| Frontend | Vanilla **JavaScript**, **HTML**, **CSS** (glassmorphic UI) |
| Optional backend | **Python** + **Flask** (audit metadata logging to SQLite) |
| Unit testing | **Vitest** |
| End-to-end testing | **Playwright** |

## 📂 Project Structure

```
OmniGupt/
├── index.html                   # Main app UI
├── index.js                     # App entry logic
├── index-bundle.js              # Bundled application script
├── index.css                    # Styles
├── ciphersense-engine.js        # CipherSense format-detection logic
├── ciphersense-ui.js            # CipherSense UI bindings
├── history.html                 # Local audit history viewer
├── server.py                    # Optional Flask logging server
├── requirements.txt             # Python dependencies
├── package.json                 # Node scripts & dev dependencies
├── playwright.config.js         # E2E test config
├── vitest.config.js             # Unit test config
├── tests/                       # Test suite (unit, security, e2e)
├── AES_GCM_IMPLEMENTATION.md    # AES-GCM implementation notes
├── LEGACY_CRYPTO_POLICY.md      # Legacy cipher policy
├── SECURITY_FIXES.md            # Security fix log
├── TAMPER_DETECTION_LAB.md      # Tamper Detection Lab notes
├── AVALANCHE_EFFECT_LAB.md      # Avalanche Effect Lab notes
├── SECURE_AUDIT_HISTORY.md      # Audit/history logging notes
└── UI_UX_UPGRADE.md             # UI/UX changelog
```

## 🚀 Getting Started

### Prerequisites

- Any modern browser (Chrome, Firefox, Edge, Safari)
- [Node.js](https://nodejs.org/) 18+ (only needed for running tests)
- [Python](https://python.org/) 3.8+ (only needed for the optional logging server)

### Option 1 — Static, zero install (fastest)

```bash
git clone https://github.com/TheCyberUchiha/OmniGupt.git
cd OmniGupt
```

Open `index.html` directly in your browser (double-click it, or open via `file://`). That's it — no build step, no server required.

### Option 2 — With optional local audit logging

If you want operation metadata logged to a local SQLite database:

```bash
pip install -r requirements.txt
python server.py
```

The server starts at `http://localhost:5000/`. OmniGupt auto-detects the backend and logs safe, non-sensitive metadata to it (algorithm, operation type, status, payload size, timestamp — never your actual secrets). View logged history by opening `history.html`.

## 📘 Usage

1. **Encrypt** — choose a cipher (AES-256-GCM recommended), enter a passphrase or generate a random key, paste your plaintext, and hit **Initiate Encryption**.
2. **Decrypt** — paste your ciphertext into the decrypt panel; OmniGupt auto-detects the format and prompts you for the matching key/passphrase.
3. **Analyze** — paste any unknown string into **CipherSense** to get a ranked breakdown of likely formats (hash type, encoding, ciphertext shape).
4. **Explore the Security Lab** — try the Tamper Detection Lab to see authentication failure in action, or the Avalanche Effect Visualizer to see how a one-character change cascades through a cipher.

## ✅ Running Tests

```bash
npm install

npm run test:unit      # Vitest unit tests
npm run test:security  # Static security scan (tests/security-scan.js)
npm run test:e2e       # Playwright end-to-end tests

npm run test:all       # Run everything
```

## 🔐 Security & Privacy Model

- All cryptographic operations execute **client-side**, in-browser.
- Plaintext, passphrases, and keys are **never persisted** — memory only, cleared on reload.
- Only non-sensitive **audit metadata** is optionally logged, and only if you run the local Flask server yourself.
- Legacy ciphers (DES, 3DES, AES-CBC, Rabbit) are included strictly for **education and retro-compatibility** — not recommended for real, sensitive data. Use AES-256-GCM for that.
- This is an educational/developer toolkit, not a certified or professionally audited security product. Evaluate your own requirements before using any browser-based tool for production-sensitive data.

## 📚 Documentation

Deeper technical write-ups live alongside the code:

| Doc | Covers |
|---|---|
| `AES_GCM_IMPLEMENTATION.md` | AES-GCM implementation details |
| `LEGACY_CRYPTO_POLICY.md` | Why and how legacy ciphers are handled |
| `SECURITY_FIXES.md` | History of security-relevant fixes |
| `TAMPER_DETECTION_LAB.md` | Tamper Detection Lab internals |
| `AVALANCHE_EFFECT_LAB.md` | Avalanche Effect Visualizer internals |
| `SECURE_AUDIT_HISTORY.md` | Audit logging design |
| `UI_UX_UPGRADE.md` | UI/UX changelog |

## ❓ FAQ

<details>
<summary><b>Is it safe to encrypt real sensitive data with this?</b></summary>
<br>
AES-256-GCM here uses the browser's native, standards-compliant Web Crypto API, which is solid. That said, this is an educational/developer tool without a professional security audit — for production-sensitive data, do your own risk assessment first.
</details>

<details>
<summary><b>Why include broken ciphers like DES?</b></summary>
<br>
Purely for education — seeing DES/3DES/Rabbit fail or behave differently next to AES-256-GCM is a better teacher than a paragraph explaining why they're deprecated. They're clearly labeled and never the default.
</details>

<details>
<summary><b>Does OmniGupt work offline?</b></summary>
<br>
Yes — once loaded, the core app runs entirely client-side and works from the local filesystem (<code>file://</code>). The optional Flask server for audit logging is the only part that needs anything running locally.
</details>

<details>
<summary><b>Do I need to run the Python server?</b></summary>
<br>
No — it's entirely optional and only adds local audit-history logging. The core encrypt/decrypt/analyze features work without it.
</details>

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes and add/update tests where relevant
4. Run `npm run test:all` before opening a PR
5. Commit with a clear message and push: `git push origin feature/your-feature`
6. Open a pull request describing what changed and why

## 📄 License

No license file is currently published in this repository. Until one is added, all rights are reserved by the author by default. If you want this project to be freely reusable, consider adding an [MIT License](https://choosealicense.com/licenses/mit/) — it's the most common choice for educational tools like this one.

## ⚠️ Disclaimer

OmniGupt is provided for educational and developer use. It comes with no warranties, compliance certifications, or professional cryptographic audits. Don't use it to protect real sensitive data in production without your own independent security review.

## 🙏 Acknowledgments

- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) — native browser cryptography
- [CryptoJS](https://github.com/brix/crypto-js) — legacy cipher support
- [Flask](https://flask.palletsprojects.com/) — optional local audit server
- [Vitest](https://vitest.dev/) & [Playwright](https://playwright.dev/) — testing

---

<div align="center">

Built by [**TheCyberUchiha**](https://github.com/TheCyberUchiha)

⭐ If you find this useful, consider starring the repo!

</div>
