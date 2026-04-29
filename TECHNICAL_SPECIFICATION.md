# Myki-Inspired Password Manager: Technical Specification

## Executive Summary

This document provides a comprehensive technical blueprint for building an open-source, mobile-first, offline-only password manager inspired by **Myki** - the pioneering password manager that operated from 2016 until its acquisition by JumpCloud in February 2022.

### Historical Context

| Aspect                 | Detail                                                       |
| ---------------------- | ------------------------------------------------------------ |
| **Original Developer** | Myki Security                                                |
| **Founded**            | 2016 (Beirut, Lebanon)                                       |
| **Initial Funding**    | BECO Capital investment, March 2016                          |
| **Final Version**      | 1.4.10 (discontinued)                                        |
| **Acquired**           | February 2022 by JumpCloud (Louisville, Colorado)            |
| **Key Innovation**     | First password manager with true P2P sync (no cloud storage) |

Myki was revolutionary for its time, offering:

- **No cloud dependency**: All data stored locally with optional P2P sync
- **Browser extension integration**: First to offer seamless mobile-to-desktop sync
- **Zero-knowledge architecture**: Server never saw unencrypted data
- **Local-first approach**: Core functionality worked completely offline

This modern recreation aims to capture Myki's innovative spirit while leveraging contemporary technologies like CRDTs, modern cryptography, and improved P2P protocols.

---

## Myki's Original Architecture (2016-2022)

Myki pioneered several architectural concepts that this rebuild will expand upon:

1. **Local-First Storage**: Encrypted vault stored on-device (SQLCipher)
2. **P2P Sync Protocol**: Direct device-to-device communication via relay servers
3. **Biometric Unlock**: FaceID/TouchID integration on mobile
4. **Browser Bridge**: Native messaging between mobile app and browser extension
5. **Shared Key Model**: Master password derived keys shared across devices

---

## Table of Contents

1. [Core Principles](#core-principles)
2. [Storage Architecture](#1-storage-architecture)
3. [P2P Syncing Logic](#2-p2p-syncing-logic)
4. [Security Protocol](#3-security-protocol)
5. [2FA & TOTP Integration](#4-2fa-totp-integration)
6. [Tech Stack Recommendations](#5-tech-stack-recommendations)
7. [Key Considerations](#6-key-considerations)
8. [Implementation Roadmap](#7-implementation-roadmap)
9. [Security Threat Model](#8-security-threat-model)

---

## Core Principles

| Principle            | Implementation                                                             |
| -------------------- | -------------------------------------------------------------------------- |
| **Zero-Knowledge**   | All encryption/decryption happens client-side; server never sees plaintext |
| **Local-First**      | Primary data store is on-device; sync is enhancement, not requirement      |
| **Defense in Depth** | Multiple security layers (biometric + master password)                     |
| **Open Source**      | Full transparency enables community security auditing                      |
| **Offline-Capable**  | Core functionality works without any network connectivity                  |

---

## 1. Storage Architecture

### 1.1 Primary Encrypted Vault

#### Database Choice: SQLCipher (Recommended)

SQLCipher provides transparent 256-bit AES encryption for SQLite databases, making it ideal for local vault storage.

**Why SQLCipher over alternatives:**

- **Performance**: Native compiled, faster than JavaScript-based encryption
- **Maturity**: Battle-tested in production password managers (1Password, Bitwarden)
- **SQLite benefits**: ACID compliance, JSON support, full-text search
- **Cross-platform**: iOS, Android, Desktop all supported

**Alternative Considered:**

- **Age/JSON files**: Simpler but lacks query capabilities; not recommended for 1000+ credentials

#### Vault Schema

```sql
-- Core vault structure
CREATE TABLE vault_metadata (
    id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    version INTEGER DEFAULT 1,
    device_id TEXT NOT NULL,
    sync_state TEXT DEFAULT 'synced' -- synced, pending, conflict
);

CREATE TABLE credentials (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL,
    title_encrypted BLOB NOT NULL,          -- Encrypted with vault key
    username_encrypted BLOB,
    password_encrypted BLOB NOT NULL,
    url_pattern TEXT,
    notes_encrypted BLOB,
    folder_id TEXT,
    tags TEXT,                              -- JSON array
    custom_fields_encrypted BLOB,           -- JSON array, encrypted
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    last_used_at INTEGER,
    use_count INTEGER DEFAULT 0,
    favorite INTEGER DEFAULT 0,
    FOREIGN KEY (vault_id) REFERENCES vault_metadata(id)
);

CREATE TABLE identities (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL,
    title_encrypted BLOB NOT NULL,
    first_name_encrypted BLOB,
    last_name_encrypted BLOB,
    email_encrypted BLOB,
    phone_encrypted BLOB,
    address_encrypted BLOB,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE secure_notes (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL,
    title_encrypted BLOB NOT NULL,
    content_encrypted BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE folders (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL,
    name_encrypted BLOB NOT NULL,
    parent_id TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE totp_secrets (
    id TEXT PRIMARY KEY,
    credential_id TEXT,
    secret_encrypted BLOB NOT NULL,         -- AES-encrypted TOTP seed
    algorithm TEXT DEFAULT 'SHA1',
    digits INTEGER DEFAULT 6,
    period INTEGER DEFAULT 30,
    issuer TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (credential_id) REFERENCES credentials(id)
);

-- Sync tracking for CRDT
CREATE TABLE sync_log (
    id TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,              -- credential, identity, etc.
    entity_id TEXT NOT NULL,
    operation TEXT NOT NULL,                -- CREATE, UPDATE, DELETE
    timestamp INTEGER NOT NULL,
    device_id TEXT NOT NULL,
    vector_clock TEXT NOT NULL,            -- JSON encoded vector clock
    payload_hash TEXT NOT NULL,            -- SHA-256 of encrypted payload
    conflict_resolved INTEGER DEFAULT 0
);

CREATE INDEX idx_credentials_vault ON credentials(vault_id);
CREATE INDEX idx_credentials_url ON credentials(url_pattern);
CREATE INDEX idx_sync_log_entity ON sync_log(entity_type, entity_id);
CREATE INDEX idx_sync_log_vector ON sync_log(vector_clock);
```

#### Encryption Key Hierarchy

```
┌─────────────────────────────────────────────────────┐
│                  Master Password                    │
│                        │                            │
│                        ▼                            │
│              ┌─────────────────┐                     │
│              │   Argon2id     │                     │
│              │   (memory=64MB │                     │
│              │    iterations=3│                     │
│              │    parallelism=4)                    │
│              └────────┬───────┘                     │
│                       ▼                             │
│              ┌─────────────────┐                    │
│              │   Master Key    │  256-bit           │
│              │   (derived)     │                    │
│              └────────┬────────┘                    │
│                       │                             │
│           ┌───────────┼───────────┐                │
│           ▼           ▼           ▼                 │
│    ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│    │ Vault Key│ │Auth Key  │ │  MAC Key │          │
│    │ (data)   │ │(biometric│ │ (integrit│          │
│    │          │ │ unlock)  │ │  y)      │          │
│    └────┬─────┘ └────┬─────┘ └────┬─────┘          │
│         │            │            │                 │
│         ▼            ▼            ▼                 │
│    Encrypts     Secures      Verifies               │
│    Vault DB     Biometric    Data                    │
│                 Ref Key       Integrity              │
└─────────────────────────────────────────────────────┘
```

### 1.2 Biometric Unlock Ref Key Storage

**iOS (Keychain with biometric protection):**

```swift
// Store derived key in Secure Enclave-backed Keychain
let accessControl = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    [.biometryCurrentSet, .privateKeyUsage],
    nil
)

// Store encrypted vault key derived from master password
// Key protected by Face ID/Touch ID + device passcode
```

**Android (Android Keystore):**

```kotlin
// Use Android Keystore with BiometricPrompt
val keyInfo = KeyFactory.getInstance(masterKey.algorithm)
    .getKeySpec(masterKey, InvalidKeySpecException::class.java)

// Key authenticated with biometric + device credentials
```

### 1.3 Database Encryption Parameters

```javascript
// SQLCipher configuration
const CIPHER_CONFIG = {
  // Encryption algorithm
  cipher: "AES-256-CBC",

  // Key derivation (handled separately via Argon2)
  kdf_iterations: 1, // SQLCipher KDF disabled; we use Argon2

  // HMAC for authentication
  hmac_algorithm: "SHA256",

  // Page size
  cipher_page_size: 4096,

  // PBKDF2 is disabled; Argon2id used instead
  // SQLCipher's fast_kdf option can be enabled
  fast_kdf: 1,
};
```

---

## 2. P2P Syncing Logic

### 2.1 Architecture Overview

```
┌──────────────┐         ┌──────────────┐
│   Mobile A   │◄───────►│   Mobile B   │
│   (iOS)      │   P2P   │   (Android)  │
└──────┬───────┘         └──────┬───────┘
       │                        │
       │    ┌──────────────┐   │
       └───►│  Relay Server │◄──┘
            │  (metadata   │
            │   only, never │
            │   sees keys)  │
            └──────────────┘
                   ▲
                   │ (optional, for NAT traversal)
                   │
            ┌──────┴───────┐
            │   Signaling  │
            │   Server     │
            └──────────────┘
```

### 2.2 Sync Protocol: Encrypted Payload Exchange

**Phase 1: Device Discovery & Handshake**

```
Mobile A                          Relay Server                    Mobile B
   │                                   │                              │
   │─── Register: {device_id, pubkey} ─►                              │
   │◄── Ack ──────────────────────────│                              │
   │                                   │                              │
   │                                   │─── Peer Online Query ────────►│
   │                                   │◄── Response ────────────────│
   │                                   │                              │
   │◄──────────── SDP Offer ───────────│                              │
   │                                   │                              │
   │──────────── SDP Answer ──────────►│                              │
```

**Phase 2: E2E Encrypted Data Exchange (WebRTC DataChannel)**

```typescript
// Payload structure for sync message
interface SyncMessage {
  header: {
    message_id: string; // UUID
    timestamp: number; // Unix ms
    sender_device_id: string;
    recipient_device_id: string;
    vector_clock: VectorClock; // For CRDT ordering
    payload_type: "full_sync" | "delta_sync" | "conflict_resolution";
  };
  encrypted_body: {
    algorithm: "AES-256-GCM";
    iv: string; // Base64 12-byte nonce
    ciphertext: string; // Base64 encrypted payload
    auth_tag: string; // Additional authentication
  };
  signature: string; // Ed25519 signature of header
}

// Vector clock for causality tracking
interface VectorClock {
  [device_id: string]: number; // Incremented per device per operation
}
```

**Phase 3: Sync Payload Content**

```typescript
// Delta sync payload (minimal bandwidth)
interface DeltaSyncPayload {
  changes_since_vector_clock: VectorClock;
  changes: SyncChange[];
}

interface SyncChange {
  entity_type: "credential" | "identity" | "note" | "folder" | "totp";
  entity_id: string;
  operation: "create" | "update" | "delete";
  vector_clock: VectorClock;
  encrypted_blob: string; // Entire entity encrypted as blob
  blob_hash: string; // SHA-256 for integrity
  previous_vector_clock: VectorClock; // For conflict detection
}
```

### 2.3 Relay Server Role (Minimal Trust)

The relay server **never** has access to:

- Master password
- Derived keys
- Encrypted vault data
- Any credentials or secrets

The relay server only handles:

- Device discovery (public keys only)
- SDP signaling for WebRTC
- Encrypted message relay (opaque blobs)
- Offline message queue (TTL: 24 hours, encrypted)

```typescript
// Relay server message format
interface RelayMessage {
  id: string;
  from: string; // device_id
  to: string; // device_id
  encrypted_payload: string; // Entirely opaque to relay
  expires_at: number; // Auto-delete timestamp
  created_at: number;
}
```

### 2.4 WebRTC Data Channel Setup

```typescript
const rtcConfig: RTCConfiguration = {
  iceServers: [
    // STUN servers for public IP discovery
    { urls: "stun:stun.l.google.com:19302" },
    // TURN server (optional, for symmetric NAT)
    {
      urls: "turn:your-turn-server.com",
      username: "anonymous",
      credential: "anonymous",
    },
  ],
  iceCandidatePoolSize: 10,
  bundlePolicy: "max-bundle",
  rtcpMuxPolicy: "require",
};

// Data channel for vault sync
const dataChannel = peerConnection.createDataChannel("vault_sync", {
  ordered: true, // Required for CRDT ordering
  maxPacketLifeTime: 30000, // 30 second retry window
});

// Encryption: All data is double-encrypted
// Layer 1: End-to-end encryption with shared vault key
// Layer 2: TLS/DTLS transport encryption
```

---

## 3. Security Protocol

### 3.1 Master Password Derivation: Argon2id

**Why Argon2id:**

- Winner of Password Hashing Competition (2015)
- Memory-hard: Resistant to GPU/ASIC attacks
- Adaptive: Easy to increase parameters as hardware improves
- Three variants: Argon2d (GPU resistant), Argon2i (side-channel resistant), Argon2id (hybrid)

**Parameters:**

```typescript
const ARGON2_CONFIG = {
  algorithm: "argon2id",

  // Memory hardness: 64 MB
  memory: 64 * 1024 * 1024, // 64 MiB

  // CPU/iterations: 3 passes
  iterations: 3,

  // Parallelism: 4 lanes (matches typical quad-core)
  parallelism: 4,

  // Output: 256-bit (32 bytes) master key
  hashLength: 32,

  // Salt: 256-bit (32 bytes) random, stored encrypted
  saltLength: 32,

  // Version
  version: 0x13, // 0x13 = 19 (latest)
};

// Derived keys
const derivedKey = argon2id(
  password,
  salt,
  ARGON2_CONFIG.memory,
  ARGON2_CONFIG.iterations,
  ARGON2_CONFIG.parallelism,
  ARGON2_CONFIG.hashLength,
);

// Split derived key
const vaultKey = derivedKey.slice(0, 32); // AES-256 key
const macKey = derivedKey.slice(32, 64); // HMAC key
```

**Alternative: PBKDF2 (Fallback for compatibility)**

```typescript
const PBKDF2_CONFIG = {
  algorithm: "PBKDF2",
  hash: "SHA-256",
  iterations: 600_000, // OWASP 2023 recommendation
  keyLength: 64, // 32 bytes vault key + 32 bytes MAC key
  saltLength: 32,
};
```

### 3.2 Biometric Authentication Flow

```
┌────────────────────────────────────────────────────────────┐
│                      UNLOCK FLOW                            │
├────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐   │
│  │   Biometric │───►│  Validate   │───►│   Retrieve  │   │
│  │   Prompt    │    │  Biometric  │    │  Ref Key    │   │
│  │   (Face ID) │    │  Signature  │    │  from Kchain│   │
│  └─────────────┘    └──────┬──────┘    └──────┬──────┘   │
│                            │                   │           │
│                     Success│                   │           │
│                            ▼                   ▼           │
│                     ┌─────────────────────────────┐       │
│                     │   Decrypt Vault Key with    │       │
│                     │   Ref Key + Device Auth     │       │
│                     └──────────────┬──────────────┘       │
│                                    │                       │
│                                    ▼                       │
│                     ┌─────────────────────────────┐       │
│                     │   Open SQLCipher Vault      │       │
│                     │   with Decrypted Key        │       │
│                     └─────────────────────────────┘       │
│                                                             │
└────────────────────────────────────────────────────────────┘
```

**iOS Implementation:**

```swift
class BiometricAuthService {
    private let keychain = Keychain(service: "com.myki.vault")

    func unlockWithBiometric() async throws -> Data? {
        let context = LAContext()
        context.localizedReason = "Unlock your password vault"

        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                        error: &error) else {
            throw BiometricError.notAvailable
        }

        let result = try await context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: "Unlock your password vault"
        )

        guard result else { throw BiometricError.failed }

        // Retrieve biometric-protected key from Keychain
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.myki.vault",
            kSecAttrAccount as String: "vault_key_ref",
            kSecReturnData as String: true,
            kSecUseAuthenticationContext as String: context
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status == errSecSuccess, let keyData = item as? Data else {
            throw BiometricError.keyNotFound
        }

        return keyData
    }
}
```

### 3.3 Session Management

```typescript
interface SessionManager {
    // Session key derived from vault key + session salt
    // Auto-lock timers
    const AUTO_LOCK_CONFIG = {
        immediate: 0,              // Lock on background
        oneMinute: 60,             // 1 minute background
        fiveMinutes: 300,         // 5 minutes background
        fifteenMinutes: 900,      // 15 minutes background
        oneHour: 3600,            // 1 hour background
        fourHours: 14400,         // 4 hours background
        never: -1                 // Never (not recommended)
    };

    // Memory protection
    const SESSION_CONFIG = {
        clearClipboardTimeout: 30,        // Clear copied passwords after 30s
        screenSecurityEnabled: true,      // Blur app in app switcher
        jailbreakDetection: true,         // Warn on jailbroken devices
        emulatorDetection: true,          // Block emulators
        debugDetection: true,             // Block debug mode in release
    };
}
```

### 3.4 Emergency Access

```typescript
// Emergency access: Grant vault access to trusted contacts
interface EmergencyAccess {
  // Share encrypted recovery package with trusted contacts
  recoveryPackage: {
    encrypted_vault_key: string; // Encrypted with trusted contact's public key
    allowed_after_seconds: number; // Time before access granted (e.g., 7 days)
    access_level: "view" | "full";
  };

  // Audit trail
  access_request_log: {
    requested_at: number;
    requester_public_key: string;
    vault_owner_notified: boolean;
    auto_approve_after: number;
  };
}
```

---

## 4. 2FA & TOTP Integration

### 4.1 TOTP Implementation

**RFC 6238 compliant implementation:**

```typescript
interface TOTPConfig {
  algorithm: "SHA1" | "SHA256" | "SHA512"; // Default: SHA1 (standard)
  digits: 6 | 8; // Default: 6
  period: number; // Default: 30 seconds
  issuer: string; // Service name
  accountName: string; // User email/name
}

class TOTPSecret {
  readonly encryptedSeed: Uint8Array; // AES-encrypted TOTP seed
  readonly config: TOTPConfig;

  generateCode(timestamp: number = Date.now()): string {
    // Decrypt seed
    const seed = this.decryptSeed();

    // Convert time to counter
    const counter = Math.floor(timestamp / 1000 / this.config.period);

    // Generate HOTP
    const code = this.hotp(seed, counter);

    return code.padStart(this.config.digits, "0");
  }

  private hotp(secret: Uint8Array, counter: number): number {
    // Convert counter to 8-byte buffer
    const counterBytes = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
      counterBytes[7 - i] = (counter >> (8 * i)) & 0xff;
    }

    // HMAC
    const hmac = crypto.createHmac(this.config.algorithm, secret);
    hmac.update(counterBytes);
    const hash = hmac.digest();

    // Dynamic truncation
    const offset = hash[hash.length - 1] & 0x0f;
    const binary =
      ((hash[offset] & 0x7f) << 24) |
      ((hash[offset + 1] & 0xff) << 16) |
      ((hash[offset + 2] & 0xff) << 8) |
      (hash[offset + 3] & 0xff);

    return binary % Math.pow(10, this.config.digits);
  }

  private decryptSeed(): Uint8Array {
    // Decrypt using vault key
    return crypto.aesDecrypt(this.encryptedSeed, this.vaultKey);
  }
}
```

### 4.2 QR Code Import/Export

```typescript
interface TOTPExportFormat {
    // otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example
    parseOtpAuthUri(uri: string): TOTPConfig {
        const url = new URL(uri);
        if (url.protocol !== 'otpauth:') {
            throw new Error('Invalid TOTP URI');
        }

        const path = url.pathname.slice(1); // Remove leading /
        const [issuer, accountName] = path.split(':');

        return {
            algorithm: (url.searchParams.get('algorithm') || 'SHA1').toUpperCase(),
            digits: parseInt(url.searchParams.get('digits') || '6'),
            period: parseInt(url.searchParams.get('period') || '30'),
            issuer: url.searchParams.get('issuer') || issuer,
            accountName: decodeURIComponent(accountName || url.searchParams.get('account') || ''),
            secret: url.searchParams.get('secret') || '',
        };
    }
}
```

### 4.3 2FA Auto-Fill Integration

**iOS AutoFill Extension:**

```swift
// AutoFill credential + TOTP from browser
class AutoFillCredentialProvider: ASCredentialProviderViewController {
    func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) throws {
        // Quick unlock with biometrics
        let context = LAContext()
        try context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: nil)

        // Retrieve credential
        let credential = try vaultService.getCredential(for: credentialIdentity)

        // Auto-fill password
        let passwordCredential = ASPasswordCredential(
            user: credential.username,
            password: credential.password
        )
        extensionContext.completeRequest(withSelectedCredential: passwordCredential)

        // If TOTP available, copy to clipboard
        if let totpCode = credential.totp?.currentCode {
            UIPasteboard.general.string = totpCode
            // Clear after 30 seconds
            DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
                if UIPasteboard.general.string == totpCode {
                    UIPasteboard.general.string = ""
                }
            }
        }
    }
}
```

### 4.5 2FA Roadmap

| Phase       | Feature                                 | Priority |
| ----------- | --------------------------------------- | -------- |
| **Phase 1** | TOTP code generation                    | Critical |
| **Phase 1** | QR code scanning import                 | Critical |
| **Phase 2** | Push notification for approval requests | High     |
| **Phase 2** | Yubikey NFC/ Lightning support          | High     |
| **Phase 3** | Hardware key management                 | Medium   |
| **Phase 3** | Passkey (WebAuthn) credential storage   | Medium   |
| **Phase 4** | Backup codes management                 | Low      |

---

## 5. Tech Stack Recommendations

### 5.1 Primary Recommendation: Flutter + Rust Core

```
┌────────────────────────────────────────────────────────────┐
│                    PRESENTATION LAYER                       │
│                        Flutter UI                          │
│                    (iOS, Android, Web)                     │
├────────────────────────────────────────────────────────────┤
│                      BUSINESS LOGIC                         │
│                    Flutter/Dart Code                        │
│              (State management, UI logic)                   │
├────────────────────────────────────────────────────────────┤
│                        FFI BRIDGE                           │
│                      Dart FFI (C-call)                      │
├────────────────────────────────────────────────────────────┤
│                       CORE CRYPTO                           │
│                    Rust (Native Binaries)                  │
│          ┌─────────────────────────────────────┐           │
│          │  ┌─────────┐  ┌─────────┐  ┌───────┐│           │
│          │  │ Argon2  │  │ AES-GCM │  │  OPRF ││           │
│          │  │  (via   │  │ +ChaCha │  │( Privacy│           │
│          │  │ argon2) │  │  Poly   │  │ Pass) ││           │
│          │  └─────────┘  └─────────┘  └───────┘│           │
│          │                                      │           │
│          │  ┌─────────┐  ┌─────────┐  ┌───────┐│           │
│          │  │ SQLCipher│  │  TOTP   │  │ CRDT  ││           │
│          │  │(rusqlite)│  │(totp-rs)│  │(yjs) ││           │
│          │  └─────────┘  └─────────┘  └───────┘│           │
│          └─────────────────────────────────────┘           │
├────────────────────────────────────────────────────────────┤
│                    PLATFORM INTEGRATION                     │
│              iOS Keychain │ Android Keystore                 │
└────────────────────────────────────────────────────────────┘
```

**Why Flutter + Rust:**

- **Performance**: Rust core handles crypto at near-C speed
- **Security**: No JavaScript engine = smaller attack surface
- **Cross-platform**: Single codebase for iOS, Android, Desktop
- **Ecosystem**: Native platform features accessible via plugins
- **Bundle size**: Smaller than Electron/React Native

### 5.2 Rust Crate Dependencies

```toml
# Cargo.toml for core crypto module
[package]
name = "myki_core"
version = "0.1.0"
edition = "2021"

[dependencies]
# Cryptography
argon2 = "0.5"           # Argon2id password hashing
aes-gcm = "0.10"         # AES-256-GCM encryption
chacha20poly1305 = "0.10" # Additional authenticated encryption
rand = "0.8"             # Secure random number generation
base32 = "0.4"           # TOTP secret encoding

# Database
rusqlite = { version = "0.29", features = ["bundled"] }
sqlcipher = "0.29"        # Encrypted SQLite

# Async runtime
tokio = { version = "1", features = ["full"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# CRDT for conflict resolution
yrs = "0.17"             # Yjs Rust port

# WebRTC (for P2P sync)
webrtc = "0.7"

# Logging
tracing = "0.1"
tracing-subscriber = "0.3"

# Error handling
thiserror = "1"
anyhow = "1"

[profile.release]
opt-level = 3            # Maximum optimization
lto = true               # Link-time optimization
codegen-units = 1        # Better inlining
panic = "abort"          # Smaller binary
strip = true             # Remove debug symbols
```

### 5.3 Flutter Project Structure

```
lib/
├── main.dart
├── app.dart
├── core/
│   ├── constants/
│   │   ├── app_constants.dart
│   │   └── crypto_constants.dart
│   ├── errors/
│   │   └── exceptions.dart
│   ├── theme/
│   │   └── app_theme.dart
│   └── utils/
│       └── extensions.dart
├── data/
│   ├── datasources/
│   │   ├── local/
│   │   │   ├── vault_database.dart
│   │   │   └── secure_storage.dart
│   │   └── remote/
│   │       └── p2p_sync_service.dart
│   ├── models/
│   │   ├── credential_model.dart
│   │   ├── identity_model.dart
│   │   ├── totp_model.dart
│   │   └── sync_state_model.dart
│   └── repositories/
│       ├── vault_repository_impl.dart
│       └── sync_repository_impl.dart
├── domain/
│   ├── entities/
│   │   ├── credential.dart
│   │   ├── identity.dart
│   │   └── totp_secret.dart
│   ├── repositories/
│   │   ├── vault_repository.dart
│   │   └── sync_repository.dart
│   └── usecases/
│       ├── unlock_vault.dart
│       ├── get_credentials.dart
│       ├── save_credential.dart
│       ├── generate_totp.dart
│       └── sync_vault.dart
├── presentation/
│   ├── blocs/
│   │   ├── auth/
│   │   │   ├── auth_bloc.dart
│   │   │   ├── auth_event.dart
│   │   │   └── auth_state.dart
│   │   ├── vault/
│   │   │   ├── vault_bloc.dart
│   │   │   ├── vault_event.dart
│   │   │   └── vault_state.dart
│   │   └── sync/
│   │       ├── sync_bloc.dart
│   │       ├── sync_event.dart
│   │       └── sync_state.dart
│   ├── pages/
│   │   ├── unlock_page.dart
│   │   ├── vault_page.dart
│   │   ├── credential_detail_page.dart
│   │   ├── add_credential_page.dart
│   │   ├── settings_page.dart
│   │   └── sync_page.dart
│   └── widgets/
│       ├── credential_tile.dart
│       ├── totp_display.dart
│       ├── password_field.dart
│       └── biometric_button.dart
└── injection.dart
```

### 5.4 Alternative Stack: React Native + Native Modules

If Flutter expertise is limited, React Native with native modules is viable:

```
React Native App
    │
    ├── JavaScript Layer (UI, Business Logic)
    │
    └── Native Modules (via Bridge)
            │
            ├── iOS: Swift Crypto Module (Argon2, SQLCipher)
            │
            └── Android: Kotlin Crypto Module
```

**Trade-offs:**

- Pros: Larger developer pool, web compatibility
- Cons: JavaScript runtime attack surface, larger bundle size

### 5.5 Comparison Matrix

| Criteria       | Flutter + Rust | React Native | Electron   | Native (Swift/Kotlin) |
| -------------- | -------------- | ------------ | ---------- | --------------------- |
| Performance    | ⭐⭐⭐⭐⭐     | ⭐⭐⭐⭐     | ⭐⭐       | ⭐⭐⭐⭐⭐            |
| Security       | ⭐⭐⭐⭐⭐     | ⭐⭐⭐⭐     | ⭐⭐       | ⭐⭐⭐⭐⭐            |
| Bundle Size    | ⭐⭐⭐⭐       | ⭐⭐⭐⭐     | ⭐⭐       | ⭐⭐⭐⭐⭐            |
| Dev Speed      | ⭐⭐⭐⭐       | ⭐⭐⭐⭐⭐   | ⭐⭐⭐⭐   | ⭐⭐                  |
| Cross-Platform | ⭐⭐⭐⭐⭐     | ⭐⭐⭐⭐⭐   | ⭐⭐⭐⭐⭐ | ⭐⭐                  |

---

## 6. Key Considerations

### 6.1 Conflict Resolution with CRDTs

**The Problem:**
Without a central server, when the same credential is edited on two devices offline, a conflict arises.

**CRDT Solution:**

```typescript
// Yjs Document structure for vault
import * as Y from "yjs";

class VaultDocument {
  private doc: Y.Doc;
  private credentials: Y.Map<Y.Map<any>>;
  private vectorClock: Map<string, number>;

  constructor() {
    this.doc = new Y.Doc();
    this.credentials = this.doc.getMap("credentials");

    // Enable offline editing with automatic merge
    this.setupMergeStrategy();
  }

  private setupMergeStrategy() {
    // Yjs uses Last-Writer-Wins (LWW) registers with vector clocks
    // For credentials: prefer highest vector clock value
    // For edge cases: user prompt for manual resolution

    this.credentials.observe((event) => {
      event.changes.keys.forEach((change, key) => {
        if (change.action === "update") {
          this.detectAndResolveConflict(key);
        }
      });
    });
  }

  private detectAndResolveConflict(key: string): ConflictResolution {
    const local = this.credentials.get(key);
    const localVector = local.get("_vectorClock");

    // Compare vector clocks
    // If concurrent edits, apply conflict resolution rules
  }
}

// Conflict resolution rules
interface ConflictResolutionStrategy {
  // For simple fields: Last-Writer-Wins
  simpleFields: ["title", "username", "url"];

  // For passwords: User must manually resolve
  manualFields: ["password"];

  // For timestamps: Keep most recent
  timestampFields: ["updated_at"];
}
```

**Conflict Detection Algorithm:**

```typescript
function detectConflict(changeA: SyncChange, changeB: SyncChange): boolean {
  // Check if changes are concurrent (neither happened before the other)
  const clockA = changeA.vectorClock;
  const clockB = changeB.vectorClock;

  // Concurrent if: A doesn't happen-before B AND B doesn't happen-before A
  const aBeforeB = vectorClockHappensBefore(clockA, clockB);
  const bBeforeA = vectorClockHappensBefore(clockB, clockA);

  return !aBeforeB && !bBeforeA && clockA !== clockB;
}

function vectorClockHappensBefore(a: VectorClock, b: VectorClock): boolean {
  let aIsLess = false;
  let bIsLess = false;

  const allKeys = new Set([...Object.keys(a), ...Object.keys(b)]);

  for (const key of allKeys) {
    const aVal = a[key] || 0;
    const bVal = b[key] || 0;

    if (aVal > bVal) bIsLess = true;
    if (bVal > aVal) aIsLess = true;
  }

  return aIsLess && !bIsLess;
}
```

### 6.2 Backup Strategy

**Design Principle:** No cloud requirement, but seamless integration with existing cloud services.

**Backup Flow:**

```
┌─────────────────────────────────────────────────────────────┐
│                    BACKUP ARCHITECTURE                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌──────────────┐         ┌──────────────┐                 │
│   │   Encrypted  │         │   Backup     │                 │
│   │   Vault File  │────────►│   Export     │                 │
│   └──────────────┘         └──────┬───────┘                 │
│                                  │                          │
│                                  ▼                          │
│                          ┌──────────────┐                  │
│                          │  AES-256      │                  │
│                          │  Encrypted    │                  │
│                          │  Archive      │                  │
│                          └──────┬───────┘                  │
│                                 │                          │
│            ┌────────────────────┼────────────────────┐    │
│            │                    │                    │    │
│            ▼                    ▼                    ▼    │
│   ┌──────────────┐     ┌──────────────┐     ┌──────────────┐│
│   │    iCloud    │     │  Google      │     │  Local File  ││
│   │   (iOS)      │     │   Drive      │     │  Export      ││
│   └──────────────┘     └──────────────┘     └──────────────┘│
│                                                              │
│   Backup file is ENCRYPTED with a user-chosen backup        │
│   password (separate from master password, optionally)      │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Implementation:**

```typescript
class BackupService {
  async createEncryptedBackup(
    vault: VaultDatabase,
    backupPassword?: string,
  ): Promise<BackupArchive> {
    // Use separate backup key derived from backup password
    // Or use vault key with additional layer
    const backupKey = backupPassword
      ? this.deriveBackupKey(backupPassword)
      : this.vaultKey; // Single password mode

    // Export vault to encrypted JSON
    const vaultExport = await vault.exportAll();
    const encryptedPayload = await this.encryptVault(vaultExport, backupKey);

    return {
      version: "1.0",
      created_at: Date.now(),
      algorithm: "AES-256-GCM",
      encrypted_data: encryptedPayload,
      checksum: sha256(encryptedPayload),
    };
  }

  async restoreFromBackup(
    archive: BackupArchive,
    password: string,
  ): Promise<VaultDatabase> {
    const backupKey = this.deriveBackupKey(password);
    const decrypted = await this.decryptVault(
      archive.encrypted_data,
      backupKey,
    );

    // Verify checksum
    if (sha256(archive.encrypted_data) !== archive.checksum) {
      throw new BackupCorruptedError();
    }

    return VaultDatabase.importAll(decrypted);
  }
}
```

**User Experience Prompts:**

| Event                | Prompt                                                  |
| -------------------- | ------------------------------------------------------- |
| First vault creation | "Create a backup now or set a reminder"                 |
| After 10 credentials | "Your vault is growing. Create a backup?"               |
| Monthly check-in     | "When did you last backup? [Backup Now] [Remind Later]" |
| Pre-upgrade          | "Backup before updating to ensure recovery options"     |

### 6.3 Browser Extension Integration

**Architecture:**

```
┌─────────────────────────────────────────────────────────────┐
│                    BROWSER EXTENSION                        │
│    ┌─────────────────────────────────────────────────┐     │
│    │  ┌─────────┐  ┌─────────┐  ┌─────────────────┐  │     │
│    │  │ Popup   │  │Content  │  │  Background     │  │     │
│    │  │  UI     │  │ Script  │  │  Service Worker │  │     │
│    │  └────┬────┘  └────┬────┘  └────────┬────────┘  │     │
│    └───────┼───────────┼─────────────────┼──────────┘     │
│            │           │                 │                  │
│            └───────────┴────────┬────────┘                  │
│                                │                            │
│                         Native Messaging                     │
│                                │                            │
├────────────────────────────────┼────────────────────────────┤
│                         NATIVE HOST                          │
│                                │                            │
│    ┌─────────────────────────────────────────────────────┐ │
│    │                   Local Server                       │ │
│    │                                                      │ │
│    │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │ │
│    │   │   Native    │  │   IPC       │  │  Vault      │ │ │
│    │   │   Messaging │◄─►│   Bridge    │◄─►│  Service    │ │ │
│    │   │   Handler   │  │             │  │             │ │ │
│    │   └─────────────┘  └─────────────┘  └──────┬──────┘ │ │
│    └────────────────────────────────────────────│─────────┘ │
│                                                  │           │
│    ┌─────────────────────────────────────────────┴───────┐  │
│    │              Encrypted Local Vault (SQLCipher)       │  │
│    └─────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Native Messaging Implementation:**

**Desktop App (Rust + Tauri):**

```rust
// Tauri handles native messaging automatically
#[tauri::command]
async fn get_credentials_for_url(
    url: String,
    master_key: State<MasterKeyGuard>,
) -> Result<Vec<CredentialDto>, VaultError> {
    // Validate master key (from biometric or password unlock)
    let key = master_key.validate()?;

    // Query vault for matching credentials
    let credentials = vault.get_by_url_pattern(&url)?;

    // Decrypt and return
    Ok(credentials.into_iter()
        .map(|c| c.to_dto(&key))
        .collect())
}
```

**Browser Extension (WebExtension API):**

```javascript
// background.js - Native messaging bridge
class VaultBridge {
  async getCredentials(domain) {
    const response = await browser.runtime.sendNativeMessage(
      "com.myki.app", // Native app ID
      {
        action: "getCredentialsForUrl",
        domain: domain,
      },
    );
    return response.credentials;
  }

  async fillCredential(credentialId, fillData) {
    await browser.runtime.sendNativeMessage("com.myki.app", {
      action: "autoFill",
      credentialId: credentialId,
      fillData: fillData,
    });
  }
}

// content.js - Injected into web pages
class CredentialFiller {
  constructor(bridge) {
    this.bridge = bridge;
  }

  async handleLoginForm(form) {
    const domain = window.location.hostname;
    const credentials = await this.bridge.getCredentials(domain);

    if (credentials.length === 1) {
      // Auto-fill single credential
      this.fillForm(form, credentials[0]);

      // Copy TOTP if available
      if (credentials[0].totpCode) {
        navigator.clipboard.writeText(credentials[0].totpCode);
      }
    } else if (credentials.length > 1) {
      // Show popup selector
      this.showSelector(form, credentials);
    }
  }

  fillForm(form, credential) {
    const usernameInput = form.querySelector(
      'input[type="text"], input[type="email"]',
    );
    const passwordInput = form.querySelector('input[type="password"]');

    if (usernameInput) {
      usernameInput.value = credential.username;
      this.dispatchInputEvent(usernameInput);
    }

    if (passwordInput) {
      passwordInput.value = credential.password;
      this.dispatchInputEvent(passwordInput);
    }
  }
}
```

---

## 7. Implementation Roadmap

### Phase 1: Core MVP (Months 1-3)

| Week  | Deliverable                                                  |
| ----- | ------------------------------------------------------------ |
| 1-2   | Project setup: Flutter + Rust FFI structure                  |
| 3-4   | Argon2id key derivation + master password unlock             |
| 5-6   | SQLCipher vault creation and basic CRUD                      |
| 7-8   | Biometric unlock (iOS Face ID/Touch ID, Android Fingerprint) |
| 9-10  | Credential management UI (list, detail, add, edit, delete)   |
| 11-12 | Password generator                                           |
| 13    | MVP testing and polish                                       |

### Phase 2: Security & TOTP (Months 4-5)

| Week  | Deliverable                                               |
| ----- | --------------------------------------------------------- |
| 14-15 | TOTP implementation (RFC 6238)                            |
| 16-17 | QR code scanning for TOTP import                          |
| 18-19 | Auto-fill integration (iOS AutoFill, Android Autofill)    |
| 20-21 | Clipboard management with auto-clear                      |
| 22    | Security hardening (jailbreak detection, screen security) |

### Phase 3: Sync (Months 6-8)

| Week  | Deliverable                                 |
| ----- | ------------------------------------------- |
| 23-24 | P2P WebRTC signaling server setup           |
| 25-26 | Encrypted message exchange protocol         |
| 27-28 | CRDT implementation for conflict resolution |
| 29-30 | Sync UI and conflict resolution UI          |
| 31-32 | Offline queue and retry logic               |
| 33    | Sync testing and edge cases                 |

### Phase 4: Browser Extension (Months 9-10)

| Week  | Deliverable                                  |
| ----- | -------------------------------------------- |
| 34-35 | Tauri desktop app with native messaging      |
| 36-37 | Browser extension scaffold (Chrome, Firefox) |
| 38-39 | Credential auto-fill from extension          |
| 40-41 | TOTP auto-copy from extension                |
| 42    | Extension review and store submission        |

### Phase 5: Polish & Launch (Months 11-12)

| Week  | Deliverable                      |
| ----- | -------------------------------- |
| 43-44 | Backup/restore functionality     |
| 45-46 | Emergency access feature         |
| 47-48 | Documentation and security audit |
| 49-50 | Beta testing program             |
| 51-52 | Public release                   |

---

## 8. Security Threat Model

### 8.1 Threat Categories

| Threat                 | Mitigation                                                              |
| ---------------------- | ----------------------------------------------------------------------- |
| **Device Theft**       | Master password + biometric required; auto-lock; remote wipe capability |
| **Memory Attacks**     | Sensitive data cleared immediately after use; no logging of secrets     |
| **Clipboard Attacks**  | Auto-clear after 30 seconds; warning on sensitive paste                 |
| **Screen Recording**   | Blur in app switcher; no preview in notifications                       |
| **Network Attacks**    | Zero-knowledge: server never sees plaintext; E2E encryption             |
| **Social Engineering** | No password hints stored; user education                                |
| **Brute Force**        | Argon2id with high memory/CPU cost; account lockout                     |
| **Biometric Bypass**   | Biometric unlocks encrypted key, not raw vault                          |

### 8.2 Security Checklist

- [ ] Master password never stored, only derived key hash
- [ ] Argon2id with minimum 64MB memory, 3 iterations
- [ ] All vault data encrypted with AES-256-GCM
- [ ] HMAC-SHA256 for integrity verification
- [ ] Secure random for all cryptographic operations
- [ ] No secrets in logs or crash reports
- [ ] Memory wiped after sensitive operations
- [ ] SSL pinning for any network communication
- [ ] Root/jailbreak detection with warning
- [ ] Screen capture disabled in sensitive views
- [ ] Backup files encrypted with separate key
- [ ] Regular security audits (static analysis, penetration testing)

### 8.3 Penetration Testing Scope

```
1. Static Analysis
   - Code review of crypto implementations
   - Dependency vulnerability scanning
   - Binary analysis of compiled Rust core

2. Runtime Analysis
   - Memory inspection for key leakage
   - Frida hooking for crypto bypass attempts
   - Network traffic analysis for data leakage

3. Social Engineering
   - Phishing simulation for backup extraction
   - Customer support impersonation testing

4. Physical Security
   - Device forensics on lost/stolen device
   - Cold boot attack resistance testing
```

---

## 9. Open Questions & Future Considerations

### 9.1 Architecture Decisions Pending

| Question              | Options                      | Recommendation                  |
| --------------------- | ---------------------------- | ------------------------------- |
| **Sync transport**    | WebRTC vs libp2p             | WebRTC (mature browser support) |
| **CRDT library**      | Yjs vs Automerge             | Yjs (smaller, better docs)      |
| **Desktop framework** | Tauri vs Electron            | Tauri (smaller, Rust-native)    |
| **Icon storage**      | Base64 in vault vs URL fetch | URL fetch with caching          |

### 9.2 Future Features

| Feature                          | Complexity | Priority |
| -------------------------------- | ---------- | -------- |
| Passkey (WebAuthn) storage       | High       | Medium   |
| Secure file attachments          | Medium     | Medium   |
| Travel mode (hide certain items) | Low        | High     |
| Breach monitoring (local check)  | Low        | High     |
| Password health scoring          | Low        | Medium   |
| Password sharing via secret link | Medium     | Low      |

---

## 10. Conclusion

This specification provides a comprehensive blueprint for building a Myki-inspired password manager that prioritizes:

1. **Zero-knowledge architecture**: All encryption client-side
2. **Local-first storage**: SQLCipher encrypted vault
3. **P2P sync without cloud dependency**: WebRTC + encrypted relay
4. **Strong security**: Argon2id + biometric unlock
5. **Modern tech stack**: Flutter + Rust for performance and security

The proposed architecture balances security, usability, and maintainability while avoiding the pitfalls of cloud-dependent password managers.

---

_Document Version: 1.0_  
_Last Updated: April 2026_  
_Maintainer: Myki Open Source Project_
