<div align="center">

# 🔒 OmniGupt

**Modern, browser-based cryptography toolkit — encrypt, decrypt, and analyze, all client-side.**

[![Live Demo](https://img.shields.io/badge/demo-live-brightgreen?style=for-the-badge)](https://omnigupt.vercel.app/)
[![GitHub stars](https://img.shields.io/github/stars/TheCyberUchiha/OmniGupt?style=for-the-badge)](https://github.com/TheCyberUchiha/OmniGupt/stargazers)
[![GitHub last commit](https://img.shields.io/github/last-commit/TheCyberUchiha/OmniGupt?style=for-the-badge)](https://github.com/TheCyberUchiha/OmniGupt/commits/main)

[Live App](https://omnigupt.vercel.app/) · [Report Bug](https://github.com/TheCyberUchiha/OmniGupt/issues) · [Request Feature](https://github.com/TheCyberUchiha/OmniGupt/issues)

</div>

---

## Why OmniGupt?

Most online "encrypt/decrypt" tools are black boxes — you paste text, something happens, you get output. OmniGupt shows the actual mechanics: the key derivation, the IV, the auth tag, the exact algorithm at play. It's built for people who want to *understand* encryption, not just use it — students, developers testing crypto flows, and CTF players fingerprinting unknown data.

Everything runs in your browser. Nothing you type is sent anywhere unless you deliberately run the optional local logging server.

> **Add a demo GIF here** — a 5-second clip of the Tamper Detection Lab catching a tampered byte sells this project better than any paragraph. Drop it in `/assets` and reference it as `![demo](./assets/demo.gif)`.

---

## Features

- **AES-256-GCM encryption** — the recommended default. Authenticated encryption means it doesn't just hide your data, it proves nobody tampered with it.
- **PBKDF2 key derivation** — 600,000 iterations, unique salt every time, so the same passphrase never produces the same key twice.
- **CSPRNG key generator** — one click for a truly random passphrase or hex key.
- **Legacy ciphers on tap** — AES-CBC, DES, 3DES, Rabbit — clearly labeled, kept around so you can see *why* they're considered broken instead of just being told.
- **Auto-detect on decrypt** — paste ciphertext, OmniGupt figures out the format for you.
- **Nothing persisted** — secrets live in memory only, gone on refresh.
- **CipherSense** — paste any unknown string and get a ranked guess of what it is (hash, encoding, ciphertext).
- **Security Lab** — two interactive demos, described below.

## Security Lab

Two small experiments that teach more than a textbook chapter:

- **Tamper Detection Lab** — encrypt something, flip one byte of the ciphertext, watch AES-GCM catch it instantly. This is the whole argument for authenticated encryption in 10 seconds.
- **Avalanche Effect Visualizer** — change one character of input, measure how much the output changes (Hamming distance). A good cipher should scramble the entire output, not just the part you touched.

## Cipher Reference

| Tier | Cipher | Status |
|---|---|---|
| Recommended | AES-256-GCM | Confidentiality + integrity, native Web Crypto API |
| Legacy | AES-CBC | Confidentiality only, no tamper detection |
| Educational | DES | Broken — 56-bit effective key |
| Educational | Triple DES (3DES) | Deprecated — vulnerable to Sweet32 |
| Educational | Rabbit | Obsolete stream cipher |

Legacy ciphers run through [CryptoJS](https://github.com/brix/crypto-js); AES-256-GCM and PBKDF2 use the browser's native Web Crypto API directly.

## Tech Stack

<div align="center">

![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square&logo=javascript&logoColor=black)
![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=flat-square&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=flat-square&logo=css3&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=flat-square&logo=flask&logoColor=white)
![Vitest](https://img.shields.io/badge/Vitest-6E9F18?style=flat-square&logo=vitest&logoColor=white)
![Playwright](https://img.shields.io/badge/Playwright-2EAD33?style=flat-square&logo=playwright&logoColor=white)

</div>

Frontend is vanilla JS/HTML/CSS — no framework overhead. The optional Flask + SQLite backend only exists for local audit logging. Vitest covers unit tests, Playwright covers end-to-end.

## Project Structure

```
OmniGupt/
├── index.html                   # Main app UI
├── index.js / index-bundle.js   # App logic
├── index.css                    # Styles
├── ciphersense-engine.js        # CipherSense detection logic
├── ciphersense-ui.js            # CipherSense UI bindings
├── history.html                 # Local audit history viewer
├── server.py                    # Optional Flask logging server
├── requirements.txt             # Python dependencies
├── package.json                 # Node scripts & dev dependencies
├── playwright.config.js         # E2E test config
├── vitest.config.js             # Unit test config
├── tests/                       # Unit, security, e2e test suite
└── *.md                         # Implementation & policy docs
```

## Getting Started

**Requirements:** any modern browser. Node 18+ only if you're running tests. Python 3.8+ only if you want local audit logging.

```bash
git clone https://github.com/TheCyberUchiha/OmniGupt.git
cd OmniGupt
```

**Fastest path** — just open `index.html` in your browser. No build step, no server.

**With audit logging** (optional):

```bash
pip install -r requirements.txt
python server.py
```

Runs at `http://localhost:5000/`. OmniGupt auto-detects it and logs safe metadata only — never your actual secrets. View it in `history.html`.

## Usage

1. Pick a cipher (AES-256-GCM by default), enter or generate a key/passphrase, paste your plaintext, hit **Initiate Encryption**.
2. Paste ciphertext into the decrypt panel — format is auto-detected.
3. Drop any unknown string into **CipherSense** for a ranked format guess.
4. Try the **Security Lab** to see tampering get caught, or watch the avalanche effect in action.

## Running Tests

```bash
npm install
npm run test:unit      # Vitest
npm run test:security  # Static security scan
npm run test:e2e       # Playwright
npm run test:all       # Everything
```

## Security Notes

- Everything crypto-related runs client-side. Plaintext, keys, and passphrases are never persisted.
- Only non-sensitive metadata (algorithm, operation, status, size, timestamp) is ever logged, and only if you opt in by running the local server.
- Legacy ciphers are for learning, not for protecting anything real — use AES-256-GCM for that.
- This is an educational/developer tool, not an audited security product. Do your own risk assessment before trusting it with production data.

## License

No license file exists in the repo yet — until one's added, all rights are reserved by default. Consider adding [MIT](https://choosealicense.com/licenses/mit/) if you want others to freely build on this.

---

<div align="center">

**Created by [The Cyber Uchiha](https://github.com/TheCyberUchiha)**

⭐ Star the repo if OmniGupt was useful to you.

</div>
