# Myki - P2P Password Manager

<p align="center">
  <img src="assets/images/myki_white.jpg" width="200" alt="Myki Logo"/>
</p>

<p align="center">
  <strong>A secure, local-first password manager with peer-to-peer sync</strong>
</p>

---

## 📖 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Projects](#projects)
- [Security Model](#security-model)
- [Getting Started](#getting-started)
- [Contributing](#contributing)

---

## 🌍 Overview

**Myki** is an open-source password manager designed with security and privacy as its core principles. Unlike cloud-based password managers, Myki stores all data locally on your device, giving you complete control over your sensitive information.

### Key Features

- **🔐 Local-First Security**: All encryption happens on-device. Your master password never leaves your device.
- **🧬 Cryptographic Best Practices**: Uses Argon2id for key derivation and AES-256-GCM for encryption.
- **⏱️ Two-Factor Authentication (TOTP)**: Built-in support for time-based one-time passwords.
- **📱 Cross-Platform**: Flutter for mobile (iOS/Android), Rust for core logic, Tauri for extensions.
- **🔄 Peer-to-Peer Sync**: WebRTC-based sync without centralized servers.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Myki Architecture                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│   │ Flutter App │  │  CLI Tool  │  │   Browser Extension     │ │
│   │  (Mobile)   │  │ (Terminal) │  │   (Tauri + WebExt)      │ │
│   └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘ │
│          │                │                     │               │
│          └────────────────┴─────────────────────┘               │
│                           │                                       │
│                   ┌───────▼───────┐                               │
│                   │  FFI Bridge   │                               │
│                   └───────┬───────┘                               │
│                           │                                       │
│          ┌────────────────┴────────────────┐                       │
│          ▼                                 ▼                       │
│   ┌─────────────────────────────────────────────────────────┐     │
│   │                     myki_core (Rust)                     │     │
│   │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │     │
│   │  │   crypto/   │  │    totp/    │  │     vault/      │  │     │
│   │  │  • KDF      │  │  • Generator│  │  • Database     │  │     │
│   │  │  • Keys     │  │  • RFC6238  │  │  • Models       │  │     │
│   │  │  • AES-GCM  │  │             │  │                 │  │     │
│   │  └─────────────┘  └─────────────┘  └─────────────────┘  │     │
│   └─────────────────────────────────────────────────────────┘     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **User authenticates** with master password
2. **Argon2id KDF** derives a 256-bit vault key from password + salt
3. **Vault key** encrypts/decrypts all credential data using AES-256-GCM
4. **TOTP secrets** generate time-based codes for 2FA
5. **Encrypted database** stores all data securely on disk

---

## 📁 Projects

### [`myki_core/`](myki_core/) - Rust Core Library

The cryptographic engine powering Myki. Written in Rust for memory safety and performance.

| Module                             | Purpose                                           |
| ---------------------------------- | ------------------------------------------------- |
| [`crypto/`](myki_core/src/crypto/) | Encryption, key derivation, random generation     |
| [`totp/`](myki_core/src/totp/)     | RFC 6238 TOTP code generation                     |
| [`vault/`](myki_core/src/vault/)   | Encrypted SQLite storage                          |
| [`ffi.rs`](myki_core/src/ffi.rs)   | Foreign Function Interface for non-Rust consumers |

### [`myki_app/`](myki_app/) - Flutter Mobile App

Cross-platform mobile application (iOS & Android).

| Directory                                                         | Purpose                                               |
| ----------------------------------------------------------------- | ----------------------------------------------------- |
| [`lib/core/models/`](myki_app/lib/core/models/)                   | Data structures (Credential, Identity, etc.)          |
| [`lib/core/services/`](myki_app/lib/core/services/)               | Business logic (VaultService, BiometricService, etc.) |
| [`lib/presentation/blocs/`](myki_app/lib/presentation/blocs/)     | State management (AuthBloc, VaultBloc)                |
| [`lib/presentation/pages/`](myki_app/lib/presentation/pages/)     | Screen UI (UnlockPage, VaultPage, etc.)               |
| [`lib/presentation/widgets/`](myki_app/lib/presentation/widgets/) | Reusable UI components                                |

### [`myki_cli/`](myki_cli/) - Command Line Interface

Terminal-based interface for power users.

```bash
myki_cli list                    # List all credentials
myki_cli search "github"          # Search credentials
myki_cli add "GitHub" "user@..." # Add new credential
```

### [`myki_extension/`](myki_extension/) - Browser Extension

Tauri-based browser extension for auto-fill functionality.

---

## 🔒 Security Model

### Key Derivation (Argon2id)

```
Master Password + Random Salt ──► Argon2id KDF ──► 256-bit Vault Key
                                    (64 MiB, 3 iterations)
```

**Why Argon2id?**

- Memory-hard: Resistant to GPU/ASIC attacks
- Side-channel resistant: Safe against timing attacks
- Industry standard: Winner of Password Hashing Competition

### Encryption (AES-256-GCM)

```
Plaintext + Vault Key + Random Nonce ──► AES-256-GCM ──► Ciphertext + Auth Tag
```

**Why GCM?**

- Authenticated Encryption: Confidenciality + Integrity
- Random nonce: Each encryption is unique
- Hardware accelerated: Fast on modern CPUs

### Password Storage

```
User Password ──► Derive Key ──► Hash Key ──► Store Hash
                                     │
                                     ▼
                            Verification on unlock
```

**Important**: The master password is NEVER stored. Only a hash of the derived key is stored for verification.

---

## 🚀 Getting Started

### Prerequisites

- **Rust** 1.70+ (for building core)
- **Flutter** 3.10+ (for mobile app)
- **Android SDK** / **Xcode** (for mobile development)

### Building

```bash
# Clone the repository
git clone https://github.com/your-org/myki.git
cd myki

# Build Rust core
cd myki_core
cargo build --release

# Build Flutter app
cd ../myki_app
flutter pub get
flutter run

# Build CLI
cd ../myki_cli
cargo build --release
```

### Running Tests

```bash
# Rust tests
cd myki_core
cargo test

# Flutter tests
cd ../myki_app
flutter test
```

---

## 👨‍💻 Contributing

1. **Fork** the repository
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Commit your changes** (`git commit -m 'Add amazing feature'`)
4. **Push to the branch** (`git push origin feature/amazing-feature`)
5. **Open a Pull Request**

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🙏 Acknowledgments

- **Argon2**: For the excellent password hashing algorithm
- **Flutter**: For the cross-platform UI framework
- **Rust**: For the safe and fast core library
- **SQLite**: For the reliable embedded database
