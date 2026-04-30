//! Myki Core Library
//! 
//! A secure, local-first password manager core library

/// Cryptographic primitives including encryption and key derivation
pub mod crypto;
/// Time-based One-Time Password (TOTP) generation
pub mod totp;
/// Vault data structures and database management
pub mod vault;
/// Foreign Function Interface for cross-language support
pub mod ffi;

pub use crypto::{MasterKey, VaultKey, MacKey, CryptoError, derive_key, Aes256Gcm, Argon2Config};
pub use totp::{Totp, TotpConfig, TotpError, Algorithm};
pub use vault::{Credential, Identity, SecureNote, Folder, TotpSecret, VaultError, VaultDatabase};
