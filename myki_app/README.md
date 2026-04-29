# 🔐 Myki Mobile App

This is the mobile companion application for **Myki**, a modern, local-first password manager and authenticator.

## 🌟 Features

- **Modern Aesthetics:** Built with Flutter, featuring clean typography (Google Inter), beautiful card-based layouts, and smooth animations.
- **Zero-Knowledge Architecture:** Your passwords are encrypted locally using a high-performance **Rust Core** (AES-256-GCM and Argon2id) via FFI.
- **P2P Sync:** Peer-to-peer device synchronization.
- **Built-in 2FA:** Full support for Time-based One-Time Passwords (TOTP RFC 6238).
- **Biometric Security:** Integrated with Face ID, Touch ID, and fingerprint scanners.

## 🚀 Getting Started

### Prerequisites
- [Flutter SDK](https://docs.flutter.dev/get-started/install) (version 3.8.0 or higher)
- Rust toolchain (for compiling the `myki_core` library)

### Installation

1. Navigate to the app directory:
   ```bash
   cd myki_app
   ```
2. Install Flutter dependencies:
   ```bash
   flutter pub get
   ```
3. Run the app on your connected device or emulator:
   ```bash
   flutter run
   ```

## 🏗️ Architecture

The app is built using the **BLoC pattern** for predictable state management. All cryptographic operations are offloaded to `myki_core`, a memory-safe Rust library accessed natively via Dart FFI.
