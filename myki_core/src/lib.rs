//! Myki Core Library
//! 
//! A secure, local-first password manager core library written in Rust.
//! This crate provides the cryptographic foundation for Myki, including:
//! 
//! - **Key Derivation**: Argon2id for secure password-to-key conversion
//! - **Encryption**: AES-256-GCM for authenticated encryption
//! - **TOTP**: Time-based One-Time Password generation (RFC 6238)
//! - **Vault Storage**: Encrypted SQLite database for credentials
//! - **FFI Interface**: C-compatible API for integration with other languages
//! 
//! # Example
//! 
//! ```rust
//! use myki_core::{derive_key, Aes256Gcm, VaultKey};
//! 
//! // Derive a key from password
//! let salt = [0u8; 32];
//! let master_key = derive_key("password", &salt, &Default::default()).unwrap();
//! 
//! // Encrypt data
//! let cipher = Aes256Gcm::new(&master_key.vault_key);
//! let encrypted = cipher.encrypt(b"secret data", None).unwrap();
//! ```

// ---------------------------------------------------------------------------
// Module Declarations
// ---------------------------------------------------------------------------
// Each module encapsulates related functionality. This follows Rust's
// principle of organizing code into logical units.

// Cryptographic primitives including encryption, key derivation, and key management.
// This module contains the security-critical code for password hashing and data encryption.
pub mod crypto;

/// Time-based One-Time Password (TOTP) generation according to RFC 6238.
// TOTP is commonly used for two-factor authentication (2FA).
pub mod totp;

/// Vault data structures and encrypted database management.
// The vault module handles storage and retrieval of credentials and other sensitive data.
pub mod vault;

/// Foreign Function Interface for cross-language support.
// These functions can be called from C, Dart (via FFI), or other languages.
pub mod ffi;

// ---------------------------------------------------------------------------
// Re-exports for Public API
// ---------------------------------------------------------------------------
// By re-exporting items, we allow users to access them directly from myki_core
// without needing to know the internal module structure (e.g., myki_core::VaultKey).

// From crypto module: Key types and cryptographic functions
// - MasterKey: The root key derived from user's password
// - VaultKey: 256-bit key used for AES-256-GCM encryption
// - MacKey: 256-bit key used for message authentication codes
// - CryptoError: Error type for cryptographic operations
// - derive_key: Function to derive keys using Argon2id
// - Aes256Gcm: The AES-256-GCM cipher implementation
// - Argon2Config: Configuration for the Argon2id key derivation function
pub use crypto::{
    MasterKey,    // Root key containing vault_key and mac_key
    VaultKey,     // 256-bit encryption key
    MacKey,       // 256-bit authentication key
    CryptoError,  // Cryptographic operation errors
    derive_key,   // Argon2id key derivation function
    Aes256Gcm,    // AES-256-GCM cipher
    Argon2Config, // Argon2id parameters
};

// From totp module: TOTP generation
// - Totp: Stateless TOTP code generator
// - TotpConfig: Configuration (algorithm, digits, period)
// - TotpError: TOTP generation errors
// - Algorithm: Hashing algorithm (SHA1, SHA256, SHA512)
pub use totp::{
    Totp,         // TOTP generator
    TotpConfig,   // TOTP configuration
    TotpError,    // TOTP errors
    Algorithm,    // Hashing algorithm enum
};

// From vault module: Storage and data models
// - Credential: A username/password entry
// - Identity: Personal information entry
// - SecureNote: Encrypted text note
// - Folder: Organization container
// - TotpSecret: TOTP configuration for a credential
// - VaultError: Vault operation errors
// - VaultDatabase: Encrypted SQLite database
pub use vault::{
    Credential,      // Password entry with metadata
    Identity,        // Personal information entry
    SecureNote,      // Encrypted text note
    Folder,          // Organization container
    TotpSecret,      // TOTP settings linked to credential
    VaultError,      // Vault operation errors
    VaultDatabase,   // Encrypted database handle
    // Also re-export CredentialNew for creating credentials
    CredentialNew,
};
