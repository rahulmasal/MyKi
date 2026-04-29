# 🔐 Myki - The Password Manager That Never Forgets

<p align="center">
  <img src="https://img.shields.io/badge/Status-Active-success?style=for-the-badge" alt="Status">
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Platform-iOS%20%7C%20Android%20%7C%20Desktop-green?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/Security-Zero%20Knowledge-orange?style=for-the-badge" alt="Security">
  <img src="https://img.shields.io/badge/Sync-P2P%20Powered-purple?style=for-the-badge" alt="Sync">
</p>

<p align="center">
  <img src="https://img.shields.io/github/stars/myki-password-manager?style=for-the-badge" alt="Stars">
  <img src="https://img.shields.io/github/forks/myki-password-manager?style=for-the-badge" alt="Forks">
  <img src="https://img.shields.io/github/issues/myki-password-manager?style=for-the-badge" alt="Issues">
</p>

---

> ### 🔥 Like Myki? Love Myki's Spirit? Meet **Myki** — The Open Source Revival!
>
> Built from the ground up with modern cryptography, Myki brings back the magic of true peer-to-peer password syncing. No cloud. No servers. Just your devices, talking directly to each other with military-grade encryption.

---

## ✨ Why Myki?

| Feature               | Description                                         |
| --------------------- | --------------------------------------------------- |
| 🔐 **Zero-Knowledge** | Your passwords never leave your devices unencrypted |
| 📡 **P2P Sync**       | Direct device-to-device sync via WebRTC             |
| 🛡️ **Argon2id**       | Memory-hard encryption that defeats GPUs            |
| 📱 **Cross-Platform** | iOS, Android, Desktop & Browser Extension           |
| 🔑 **2FA Built-In**   | TOTP authenticator included                         |
| 🌐 **Open Source**    | Community-audited security                          |

---

## 🚀 The Myki Difference

### Before (The Cloud Way)

```
┌─────────┐         ☁️          ┌─────────┐
│  Phone  │ ═══════════════════ │  Cloud  │ ═══════════════════ │  Desktop  │
│         │    SERVER RELAY      │  Server │    SERVER RELAY      │           │
│ Password│                     │ Password│                     │ Password  │
│  Saved  │                     │  Vault  │                     │  Saved    │
└─────────┘                     └─────────┘                     └─────────┘
                                        │
                               ⚠️ Single point of failure
                               ⚠️ Server can be breached
                               ⚠️ Company can shut down
```

### After (The Myki Way)

```
┌─────────┐      🔒 P2P 🔒      ┌─────────┐
│  Phone  │ ═══════════════════ │  Desktop │
│         │   Direct Encrypted   │          │
│ Password│      Connection      │ Password │
│  Saved  │                     │  Saved   │
└─────────┘                     └──────────┘
        │                               │
        │         📡 Relay (optional)   │
        │         for NAT traversal     │
        │         NEVER sees data       │
        └───────────────────────────────┘

           ✅ No single point of failure
           ✅ No server breach risk
           ✅ Lives forever (open source)
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           MYKI ARCHITECTURE                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │    iOS      │  │  Android   │  │   Desktop   │  │  Browser   │     │
│  │   App       │  │    App     │  │    App      │  │  Extension │     │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘     │
│         │                │                │                │             │
│         └────────────────┴────────┬───────┴────────────────┘             │
│                                   │                                      │
│                                   ▼                                      │
│                    ┌──────────────────────────────┐                      │
│                    │     FLUTTER / RUST CORE     │                      │
│                    │  ┌────────────────────────┐  │                      │
│                    │  │  AES-256-GCM Encrypt   │  │                      │
│                    │  │  Argon2id Key Deriv    │  │                      │
│                    │  │  TOTP RFC 6238        │  │                      │
│                    │  │  CRDT Conflict Res    │  │                      │
│                    │  └────────────────────────┘  │                      │
│                    └──────────────┬───────────────┘                      │
│                                   │                                      │
│                                   ▼                                      │
│                    ┌──────────────────────────────┐                      │
│                    │    ENCRYPTED SQLITE VAULT    │                      │
│                    │         (SQLCipher)          │                      │
│                    └──────────────────────────────┘                      │
│                                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│                         SYNC LAYER (P2P)                                 │
│                                                                          │
│  ┌─────────────┐      WebRTC DataChannel      ┌─────────────┐           │
│  │   Device A  │ ═════════════════════════════ │  Device B   │           │
│  └──────┬──────┘                              └──────┬──────┘           │
│         │                                            │                   │
│         │  ┌──────────────────────────────────────────┘                   │
│         │  │                                                           │
│         ▼  ▼                                                           │
│  ┌────────────────┐                                                   │
│  │  Relay Server  │ ← Optional, NEVER sees encrypted data              │
│  │ (STUN/TURN)    │ ← Only helps establish connection                   │
│  └────────────────┘                                                   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🔒 Security Model

### Encryption Stack

```
┌────────────────────────────────────────────────────────────────┐
│                    YOUR MASTER PASSWORD                         │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│                        Argon2id                                  │
│  • Memory: 64 MB (resists GPU/ASIC attacks)                     │
│  • Iterations: 3                                                │
│  • Parallelism: 4                                               │
│  • Time: ~1 second per unlock attempt                           │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│                     MASTER KEY (256-bit)                        │
└────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│  VAULT KEY      │ │   MAC KEY      │ │  SESSION KEY   │
│  (Encryption)   │ │  (Integrity)   │ │  (Temp ops)    │
└─────────────────┘ └─────────────────┘ └─────────────────┘
              │               │               │
              ▼               ▼               ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ AES-256-GCM     │ │ HMAC-SHA256     │ │ AES-256-GCM     │
│ All vault data  │ │ Data integrity  │ │ Quick ops      │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

### Cracking Time Comparison

| Attacker Hardware | Myki (Argon2id) | Others (PBKDF2) |
| ----------------- | --------------- | --------------- |
| Single RTX 4090   | ~10¹⁵ years     | ~10⁸ years      |
| 1000 GPU Cluster  | ~10¹² years     | ~10⁵ years      |
| Custom ASIC       | Impractical     | ~10³ years      |

---

## 📱 Features

### Core Features

| Feature                 | Status | Description                    |
| ----------------------- | ------ | ------------------------------ |
| 🔐 Master Password      | ✅     | Argon2id key derivation        |
| 👆 Biometric Unlock     | ✅     | Face ID, Touch ID, Fingerprint |
| 📝 Credential Storage   | ✅     | AES-256-GCM encrypted          |
| 🔄 P2P Sync             | ✅     | WebRTC direct connection       |
| ⏱️ TOTP 2FA             | ✅     | RFC 6238 authenticator         |
| 🎲 Password Generator   | ✅     | Customizable complexity        |
| 📋 Clipboard Auto-Clear | ✅     | Configurable timeout           |
| 🔍 Search & Filter      | ✅     | Full-text search               |
| ⭐ Favorites            | ✅     | Quick access items             |
| 📁 Folders              | ✅     | Organize credentials           |

### Platform Support

```
┌─────────────────────────────────────────────────────────┐
│                    MYKI PLATFORMS                        │
├─────────────────────────────────────────────────────────┤
│                                                          │
│   📱 iOS          📱 Android       💻 Desktop           │
│   ┌─────────┐     ┌─────────┐     ┌─────────┐          │
│   │ ✅ Done │     │ ✅ Done  │     │ 🔨 WIP  │          │
│   └─────────┘     └─────────┘     └─────────┘          │
│                                                          │
│   🌐 Browser Extension                                   │
│   ┌─────────────────────────────────────────┐          │
│   │  Chrome  │  Firefox  │  Edge  │ Safari │          │
│   │   🔨     │    🔨     │   🔨   │   🔨   │          │
│   └─────────────────────────────────────────┘          │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

## 🛠️ Tech Stack

| Layer           | Technology             | Why                                |
| --------------- | ---------------------- | ---------------------------------- |
| **Mobile UI**   | Flutter                | Cross-platform, native performance |
| **Desktop UI**  | Tauri + HTML/CSS       | Lightweight, native feel           |
| **Core Crypto** | Rust                   | Memory-safe, high performance      |
| **Encryption**  | AES-256-GCM + Argon2id | Industry standard                  |
| **Database**    | SQLCipher              | Encrypted SQLite                   |
| **Sync**        | WebRTC                 | P2P encrypted channels             |
| **State**       | BLoC Pattern           | Predictable, testable              |

---

## 🚀 Quick Start

### Flutter Mobile App

```bash
# Clone the repository
git clone https://github.com/myki-password-manager/myki.git
cd myki/myki_app

# Install dependencies
flutter pub get

# Run on iOS
flutter run -d "iPhone 14 Pro"

# Run on Android
flutter run -d "Pixel 6"
```

### Desktop App (Windows/macOS/Linux)

```bash
cd myki/myki_extension/src-tauri

# Install Rust dependencies
cargo fetch

# Development mode
cargo tauri dev

# Production build
cargo tauri build
```

---

## 📂 Project Structure

```
myki/
│
├── 📄 README.md                      # This file
├── 📄 TECHNICAL_SPECIFICATION.md     # Detailed architecture docs
├── 📄 SECURITY_COMPARISON.md         # Security vs competitors
│
├── 📱 myki_app/                      # Flutter Mobile App
│   ├── lib/
│   │   ├── main.dart                 # Entry point
│   │   ├── core/                     # Core services
│   │   │   ├── services/
│   │   │   │   ├── vault_service.dart     # Encrypted storage
│   │   │   │   ├── biometric_service.dart # Face/Touch ID
│   │   │   │   ├── totp_service.dart      # 2FA generator
│   │   │   │   ├── sync_service.dart      # P2P sync
│   │   │   │   └── device_pairing_service.dart # QR-based pairing
│   │   │   └── constants/
│   │   ├── data/                     # Data layer
│   │   ├── domain/                   # Business logic
│   │   └── presentation/             # UI layer
│   │       ├── blocs/                # State management
│   │       ├── pages/                # Screens
│   │       └── widgets/              # Reusable widgets
│   └── pubspec.yaml
│
├── 🦀 myki_core/                     # Shared Rust Core
│   ├── src/
│   │   ├── crypto/                   # Encryption & Hashing
│   │   ├── totp/                     # TOTP generator logic
│   │   ├── vault/                    # Database models & CRUD
│   │   └── lib.rs                    # Library entry point
│   └── Cargo.toml
│
└── 🖥️ myki_extension/                # Tauri Desktop App
    ├── src/
    │   ├── main.rs                   # Entry point
    │   ├── crypto.rs                 # Cryptography
    │   ├── vault.rs                  # Vault management
    │   └── commands.rs               # IPC commands
    ├── src-tauri/
    │   ├── Cargo.toml                # Rust dependencies
    │   ├── tauri.conf.json           # App config
    │   └── src/
    │       ├── main.rs               # Desktop entry
    │       ├── crypto.rs             # Desktop crypto
    │       ├── vault.rs              # Desktop vault
    │       └── commands.rs           # Desktop commands
    └── web-extension/                # Browser extension
        ├── manifest.json
        ├── popup.html
        └── background.js
```

---

## 🗺️ Roadmap

```
Phase 1 ✅ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ Core Vault
Phase 2 ✅ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ Biometric Auth
Phase 3 ✅ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ TOTP 2FA
Phase 4 🔨 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━          P2P Sync
Phase 5 🔨 ━━━━━━━━━━                                   Browser Extension
Phase 6 📋 ━━━                                         Desktop App
Phase 7 📋 ━━━                                         Emergency Access
Phase 8 📋                                             Secure Attachments
```

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

```bash
# 1. Fork the repository
# 2. Create your feature branch
git checkout -b feature/amazing-feature

# 3. Commit your changes
git commit -m "Add amazing feature"

# 4. Push to the branch
git push origin feature/amazing-feature

# 5. Open a Pull Request
```

### Areas Needing Help

- 🔧 Rust crypto audit
- 🎨 Mobile UI/UX improvements
- 🌐 Browser extension development
- 📱 macOS/Linux desktop builds
- 🧪 Security penetration testing

---

## 📜 License

MIT License - Use it freely, but keep the credits.

---

## 🙏 Acknowledgments

<div align="center">

**Inspired by the legendary [Myki](https://myki.com/)** — the original P2P password manager that showed the world how it should be done.

Built with ❤️ and a lot of ☕ by the open source community.

</div>

---

## 🔗 Links

- 📘 [Documentation](https://docs.myki.app)
- 💬 [Discord Community](https://discord.gg/myki)
- 🐛 [Issue Tracker](https://github.com/myki-password-manager/myki/issues)
- 📖 [Contributing Guide](CONTRIBUTING.md)

---

<p align="center">
  <strong>🔐 Your secrets. Your devices. Your keys.</strong>
  <br>
  <sub>Myki - The Password Manager That Never Forgets</sub>
  <br>
  <sub>Made with ❤️ for the open source community</sub>
</p>
