# Myki Core - Rust Security Library

<p align="center">
  <img src="https://img.shields.io/badge/Rust-1.70+-orange.svg" alt="Rust Version"/>
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"/>
</p>

---

## 📖 Overview

**myki_core** is the cryptographic heart of the Myki password manager. Written in pure Rust, it provides:

- **🔐 Secure Key Derivation** using Argon2id
- **🔒 AES-256-GCM Encryption** for authenticated encryption
- **⏱️ TOTP Generation** compliant with RFC 6238
- **💾 Encrypted Vault Storage** using SQLite
- **🌐 FFI Interface** for integration with non-Rust code (Flutter, CLI, etc.)

---

## 🏗️ Architecture

```
myki_core/
├── src/
│   ├── lib.rs          # Main entry point & public API
│   ├── ffi.rs         # Foreign Function Interface (C-compatible)
│   ├── crypto/         # Cryptographic operations
│   │   ├── mod.rs     # Module exports & shared types
│   │   ├── kdf.rs     # Key Derivation Function (Argon2id)
│   │   ├── keys.rs    # Key types (MasterKey, VaultKey, MacKey)
│   │   └── symmetric.rs # AES-256-GCM implementation
│   ├── totp/          # Time-based One-Time Password
│   │   ├── mod.rs     # Module exports
│   │   └── generator.rs # RFC 6238 implementation
│   └── vault/         # Encrypted credential storage
│       ├── mod.rs     # Module exports & error types
│       ├── models.rs  # Data structures
│       └── database.rs # SQLite operations
└── Cargo.toml         # Rust dependencies
```

---

## 🔐 Security Model

### Key Derivation: Argon2id

Argon2id is the winner of the Password Hashing Competition and is specifically designed to resist GPU-based attacks.

**Configuration Used by Myki:**

| Parameter     | Value    | Purpose                     |
| ------------- | -------- | --------------------------- |
| Memory        | 128 MiB  | Makes GPU attacks expensive |
| Iterations    | 3        | Increases computation time  |
| Parallelism   | 4        | Utilizes multiple CPU cores |
| Output Length | 64 bytes | Split into 2×32-byte keys   |

**Output:** Two 256-bit keys from 64 bytes of derived material:

- **Vault Key**: Used for AES-256-GCM encryption
- **MAC Key**: Used for message authentication (future use)

### Encryption: AES-256-GCM

AES-256 in Galois/Counter Mode provides:

- **Confidentiality**: Only authorized users can read the data
- **Integrity**: Tampering is detected automatically
- **Authentic Encryption**: Both properties combined

**Nonce Generation:** 12 bytes of cryptographically secure random data per encryption (never reused)

---

## 📚 Module Documentation

### [`crypto/`](src/crypto/) - Cryptographic Primitives

#### [`kdf.rs`](src/crypto/kdf.rs) - Key Derivation

```rust
// Derive a master key from password and salt
use myki_core::{derive_key, Argon2Config};

let config = Argon2Config::default();
let master_key = derive_key("my_secure_password", &salt_bytes, &config)?;
```

**What it does:**

1. Takes a user password and random salt
2. Runs Argon2id algorithm (memory-hard, side-channel resistant)
3. Returns 64 bytes of cryptographically derived key material

#### [`keys.rs`](src/crypto/keys.rs) - Key Types

```rust
use myki_core::MasterKey;

// MasterKey contains two 32-byte keys
let master_key = MasterKey::from_derived(derived_bytes);
let vault_key = master_key.vault_key;  // For encryption
let mac_key = master_key.mac_key;      // For authentication
```

**Key Types:**

- `MasterKey`: Root key containing vault_key + mac_key
- `VaultKey`: 256-bit key for AES-256-GCM encryption
- `MacKey`: 256-bit key for message authentication

#### [`symmetric.rs`](src/crypto/symmetric.rs) - AES-256-GCM

```rust
use myki_core::{Aes256Gcm, VaultKey};

let cipher = Aes256Gcm::new(&vault_key);
let encrypted = cipher.encrypt(plaintext.as_bytes(), None)?;
let decrypted = cipher.decrypt(&encrypted, None)?;
```

**Features:**

- Hardware-accelerated on modern CPUs
- Automatic authentication tag generation/verification
- Returns `EncryptedData` (nonce + ciphertext)

### [`totp/`](src/totp/) - Time-Based One-Time Passwords

#### [`generator.rs`](src/totp/generator.rs) - RFC 6238 Implementation

```rust
use myki_core::{Totp, TotpConfig, Algorithm};

let config = TotpConfig::default(); // SHA1, 6 digits, 30s
let code = Totp::now("JBSWY3DPEHPK3PXP", &config)?;
println!("Current code: {}", code); // e.g., "123456"
```

**Supported Algorithms:**

- `Algorithm::SHA1` (default, most common)
- `Algorithm::SHA256` (more secure)
- `Algorithm::SHA512` (highest security)

### [`vault/`](src/vault/) - Encrypted Storage

#### [`database.rs`](src/vault/database.rs) - SQLite Vault

```rust
use myki_core::{VaultDatabase, MasterKey};

// Create new vault (stores salt + canary automatically)
let db = VaultDatabase::create_new("vault.db", "my_password")?;

// Save credential
db.save_credential(&credential)?;

// Retrieve metadata only (no passwords)
let metas = db.get_all_credential_metas()?;

// Fetch password on demand
let password = db.get_credential_password(&credential_id)?;

// Search by title/username (returns metadata only)
let results = db.search_credential_metas("github")?;
```

**Vault Integrity**: On creation, an encrypted canary is stored. On `open()`, the canary is decrypted and verified — wrong passwords are rejected immediately.

**Database Schema:**

```sql
vault_meta      -- Key-value store for metadata
credentials     -- Encrypted credential entries
identities      -- Encrypted identity entries
secure_notes    -- Encrypted secure notes
folders         -- Encrypted folder organization
totp_secrets    -- TOTP configurations
```

#### [`models.rs`](src/vault/models.rs) - Data Structures

| Model            | Description                                              |
| ---------------- | -------------------------------------------------------- |
| `Credential`     | Username/password entry with metadata (Zeroize on drop)  |
| `CredentialMeta` | Password-free view for list/search (id, title, username) |
| `Identity`       | Personal information (name, email, phone, address)       |
| `SecureNote`     | Encrypted text note                                      |
| `Folder`         | Organization container                                   |
| `TotpSecret`     | TOTP configuration linked to a credential                |

---

## 🌐 Foreign Function Interface (FFI)

The FFI module (`ffi.rs`) provides C-compatible functions for integration with non-Rust code.

### Exported Functions

| Function               | Purpose                  |
| ---------------------- | ------------------------ |
| `myki_derive_key`      | Derive key from password |
| `myki_encrypt`         | Encrypt data             |
| `myki_decrypt`         | Decrypt data             |
| `myki_generate_totp`   | Generate TOTP code       |
| `myki_is_valid_base32` | Validate TOTP secret     |
| `myki_free_string`     | Free allocated strings   |

### Error Codes

```rust
pub enum FfiError {
    Success = 0,
    InvalidString = 1,
    DerivationFailed = 2,
    EncryptionFailed = 3,
    DecryptionFailed = 4,
    InvalidKey = 5,
}
```

### Usage from Dart/Flutter

```dart
final key = _rustBridge.deriveKey(password, saltB64);
final encrypted = _rustBridge.encrypt(plaintext, keyB64);
final code = _rustBridge.generateTotp(secret);
```

---

## 🧪 Testing

```bash
# Run all tests
cargo test

# Run with coverage
cargo test -- --nocapture

# Test specific module
cargo test crypto
cargo test totp
cargo test vault
```

---

## 📦 Dependencies

| Crate       | Version | Purpose                     |
| ----------- | ------- | --------------------------- |
| `argon2`    | 0.5     | Argon2id KDF implementation |
| `aes-gcm`   | 0.10    | AES-256-GCM encryption      |
| `hmac`      | 0.12    | HMAC for TOTP               |
| `sha1/sha2` | 0.10    | Hashing for TOTP            |
| `base64`    | 0.21    | Encoding for FFI            |
| `rusqlite`  | 0.29    | SQLite database             |
| `serde`     | 1.0     | Serialization               |
| `uuid`      | 1.0     | Unique identifiers          |
| `thiserror` | 1.0     | Error handling              |
| `zeroize`   | 1.6     | Secure memory cleanup       |

---

## 🔒 Security Considerations

1. **Memory Safety**: Rust prevents buffer overflows, use-after-free, and other memory bugs
2. **Zeroize on Drop**: `VaultKey`, `MacKey`, and `Credential` automatically zero sensitive data when dropped
3. **On-Demand Passwords**: `get_all_credential_metas()` returns metadata without passwords; passwords fetched only when needed
4. **Vault Integrity**: Encrypted canary verifies correct password on every unlock
5. **Constant-Time Comparison**: Prevents timing attacks on authentication
6. **Secure Randomness**: Uses OS CSPRNG for all random generation

---

## 📖 Further Reading

- [Argon2id Specification](https://github.com/p-h-c/phc-winner-argon2)
- [RFC 6238 - TOTP](https://datatracker.ietf.org/doc/html/rfc6238)
- [NIST AES-GCM Guidelines](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [Rust Crypto Book](https://cryptography.rs)
