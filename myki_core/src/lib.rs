//! Myki Core Library
//! 
//! A secure, local-first password manager core library

pub mod crypto;
pub mod totp;
pub mod vault;
pub mod ffi;

pub use crypto::{MasterKey, VaultKey, MacKey, CryptoError, derive_key, Aes256Gcm, Argon2Config};
pub use totp::{Totp, TotpConfig, TotpError, Algorithm};
pub use vault::{Credential, Identity, SecureNote, Folder, TotpSecret, VaultError};
