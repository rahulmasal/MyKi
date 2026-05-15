# Myki App - Flutter Mobile Application

<p align="center">
  <img src="https://img.shields.io/badge/Flutter-3.10+-02569B?style=flat-square&logo=flutter" alt="Flutter"/>
  <img src="https://img.shields.io/badge/Platform-Android%20%7C%20iOS-46c6a5?style=flat-square" alt="Platforms"/>
</p>

---

## 📖 Overview

**myki_app** is the cross-platform mobile application for Myki password manager, built with Flutter.

### Features

- **🔐 Secure Unlock**: Biometric (fingerprint/face) + Master Password
- **📋 Credential Management**: Add, view, edit, delete password entries
- **⏱️ TOTP Display**: View and copy one-time passwords
- **🔍 Search**: Find credentials by title, username, or URL
- **📋 Clipboard Integration**: Copy passwords with auto-clear security
- **🛡️ Security Hardening**: Jailbreak detection, secure screen protection

---

## 🏗️ Architecture

The app follows **Clean Architecture** with **BLoC pattern** for state management.

```
lib/
├── main.dart                    # App entry point
├── app.dart                     # Root MaterialApp widget
│
├── core/                        # Core layer (shared utilities)
│   ├── models/                  # Data models
│   │   └── credential.dart      # Credential data class
│   │
│   ├── services/                # Business logic services
│   │   ├── vault_service.dart    # Vault encryption/decryption
│   │   ├── biometric_service.dart # Biometric authentication
│   │   ├── rust_bridge_service.dart # FFI to Rust core
│   │   ├── totp_service.dart     # TOTP code generation
│   │   ├── clipboard_service.dart # Secure clipboard
│   │   └── sync_service.dart     # Cross-device sync
│   │
│   └── theme/                    # App theming
│       └── app_theme.dart        # Colors, typography, styles
│
└── presentation/                # UI layer
    ├── blocs/                    # State management (BLoC)
    │   ├── auth/                 # Authentication state
    │   │   ├── auth_bloc.dart     # Auth business logic
    │   │   ├── auth_event.dart   # Auth events
    │   │   └── auth_state.dart   # Auth states
    │   │
    │   └── vault/                # Vault state
    │       ├── vault_bloc.dart    # Vault business logic
    │       ├── vault_event.dart   # Vault events
    │       └── vault_state.dart   # Vault states
    │
    ├── pages/                    # Full screens
    │   ├── unlock_page.dart      # Lock screen / Login
    │   ├── vault_page.dart       # Main credential list
    │   └── add_credential_page.dart # Add/Edit credential
    │
    └── widgets/                   # Reusable components
        ├── credential_tile.dart   # Credential list item
        └── totp_display.dart      # TOTP countdown widget
```

---

## 🔐 Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Security Layers                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Layer 1: App Entry                                         │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ • Jailbreak Detection (FlutterJailbreakDetection)   │    │
│  │ • SecureApplication (blurs on background/screenshot)│    │
│  └─────────────────────────────────────────────────────┘    │
│                            │                                 │
│                            ▼                                 │
│  Layer 2: User Authentication                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ • Master Password (VaultService)                    │    │
│  │ • Biometric (BiometricService + LocalAuthentication)│    │
│  │ • Password-derived session key (in-memory only)      │    │
│  └─────────────────────────────────────────────────────┘    │
│                            │                                 │
│                            ▼                                 │
│  Layer 3: Data Encryption (Rust Core via FFI)               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ • Argon2id KDF (128 MiB, 3 iterations)             │    │
│  │ • AES-256-GCM (authenticated encryption)            │    │
│  │ • Encrypted SQLite database                         │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 📱 Key Screens

### Unlock Page ([`unlock_page.dart`](lib/presentation/pages/unlock_page.dart))

The entry point requiring authentication:

```
┌─────────────────────────────────┐
│                                 │
│         ┌─────────┐             │
│         │  🛡️    │  Shield Icon  │
│         └─────────┘             │
│                                 │
│       Welcome Back               │
│   Unlock your Myki vault...      │
│                                 │
│  ┌─────────────────────────┐    │
│  │ 🔒 Master Password    👁️ │    │
│  └─────────────────────────┘    │
│                                 │
│  ┌─────────────────────────┐    │
│  │     Unlock Vault        │    │
│  └─────────────────────────┘    │
│                                 │
│       ─── OR ───                │
│                                 │
│  ┌─────────────────────────┐    │
│  │    👆 Use Fingerprint   │    │
│  └─────────────────────────┘    │
│                                 │
└─────────────────────────────────┘
```

### Vault Page ([`vault_page.dart`](lib/presentation/pages/vault_page.dart))

The main credential list:

```
┌─────────────────────────────────┐
│ My Vault          🔒 Lock       │
│ Securely stored on device        │
├─────────────────────────────────┤
│ ┌─────────────────────────────┐ │
│ │ 🔍 Search credentials...   │ │
│ └─────────────────────────────┘ │
├─────────────────────────────────┤
│                                 │
│  ┌───────────────────────────┐ │
│  │ G  GitHub                  │ │
│  │    user@email.com   📋 🗑 │ │
│  └───────────────────────────┘ │
│                                 │
│  ┌───────────────────────────┐ │
│  │ G  Google                  │ │
│  │    john.doe@gmail.com 📋 🗑│ │
│  └───────────────────────────┘ │
│                                 │
│  ┌───────────────────────────┐ │
│  │ T  Twitter                 │ │
│  │    @johndoe          📋 🗑 │ │
│  └───────────────────────────┘ │
│                                 │
│                          (+)   │
└─────────────────────────────────┘
```

---

## 🧩 Core Services

### [`vault_service.dart`](lib/core/services/vault_service.dart)

Manages the vault lifecycle:

```dart
class VaultService {
  // Check if vault exists
  Future<bool> hasVault();

  // Create new vault with master password
  Future<void> createVault(String masterPassword);

  // Unlock existing vault
  Future<bool> unlockVault(String masterPassword);

  // Lock vault (clears session key)
  Future<void> lockVault();

  // Encrypt data with session key
  Future<String> encrypt(String plaintext);

  // Decrypt data with session key
  Future<String> decrypt(String encryptedData);
}
```

**Security Notes:**

- Session key is stored **only in memory** (never persisted)
- Salt stored in secure storage (Android Keystore / iOS Keychain)
- Key verification hash stored instead of actual key

### [`biometric_service.dart`](lib/core/services/biometric_service.dart)

Simplifies biometric authentication:

```dart
class BiometricService {
  // Check if biometrics available
  Future<bool> isAvailable();

  // Get available biometric types
  Future<List<BiometricType>> getAvailableBiometrics();

  // Authenticate user
  Future<bool> authenticate({String reason});
}
```

### [`rust_bridge_service.dart`](lib/core/services/rust_bridge_service.dart)

FFI bridge to Rust core:

```dart
class RustBridgeService {
  // Initialize native library (singleton)
  void initialize();

  // Derive key using Argon2id
  String? deriveKey(String password, String saltB64);

  // Encrypt using AES-256-GCM
  String? encrypt(String plaintext, String keyB64);

  // Decrypt data
  String? decrypt(String encryptedB64, String keyB64);

  // Generate TOTP code
  String? generateTotp(String secret);

  // Validate Base32 secret
  bool isValidBase32(String secret);
}
```

### [`totp_service.dart`](lib/core/services/totp_service.dart)

TOTP generation and parsing:

```dart
class TotpService {
  // Generate current TOTP code
  static String generateCode(String secret);

  // Get remaining seconds in current period
  static int getRemainingSeconds({int period = 30});

  // Get progress through current period (0.0 to 1.0)
  static double getProgress({int period = 30});

  // Parse otpauth:// URI (from QR codes)
  static TotpUriData? parseOtpAuthUri(String uri);
}
```

---

## 🔄 State Management (BLoC)

### Auth BLoC

**States:**

```dart
AuthInitial     // App just started
AuthLoading     // Authentication in progress
AuthNoVault     // No vault exists (first-time user)
AuthLocked      // Vault exists but locked
AuthAuthenticated // Vault unlocked
AuthError       // Authentication failed
```

**Events:**

```dart
AuthCheckStatus          // Check vault status on startup
AuthUnlockWithPassword  // Unlock with master password
AuthUnlockWithBiometric // Unlock with fingerprint/face
AuthLock                // Manually lock vault
AuthCreateVault         // Create new vault
```

### Vault BLoC

**States:**

```dart
VaultInitial   // Not yet loaded
VaultLoading   // Loading credentials
VaultLoaded    // Credentials loaded
VaultError     // Error occurred
```

**Events:**

```dart
VaultLoadCredentials      // Load all credentials
VaultAddCredential        // Add new credential
VaultUpdateCredential     // Update existing
VaultDeleteCredential     // Delete credential
VaultSearchCredentials    // Search/filter
```

---

## 📦 Dependencies

```yaml
dependencies:
  flutter:
    sdk: flutter

  # State Management
  flutter_bloc: ^8.1.0

  # Security
  flutter_secure_storage: ^9.0.0 # Encrypted storage
  local_auth: ^2.1.0 # Biometrics
  flutter_jailbreak_detection: ^1.10.0

  # UI
  equatable: ^2.0.5 # Value equality

  # FFI
  ffi: ^2.1.0

  # Utilities
  uuid: ^4.2.0 # Unique IDs
  otp: ^3.1.4 # TOTP parsing
  crypto: ^3.0.3 # Hashing
```

---

## 🛠️ Development

### Setup

```bash
cd myki_app

# Install dependencies
flutter pub get

# Run on Android
flutter run

# Run on iOS (requires macOS)
flutter run -d ios
```

### Testing

```bash
# Run all tests
flutter test

# Run specific test file
flutter test test/widget_test.dart
```

### Building

```bash
# Build debug APK
flutter build apk --debug

# Build release APK
flutter build apk --release

# Build iOS
flutter build ios --release
```

---

## 📖 Further Reading

- [Flutter Documentation](https://docs.flutter.dev)
- [BLoC Pattern](https://bloclibrary.dev)
- [Flutter Secure Storage](https://pub.dev/packages/flutter_secure_storage)
- [Local Authentication](https://pub.dev/packages/local_auth)
