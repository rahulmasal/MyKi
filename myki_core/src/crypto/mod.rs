//! Crypto Module
//! 
//! Cryptographic primitives for password management

pub mod kdf;
pub mod keys;
pub mod symmetric;

pub use kdf::{derive_key, KdfConfig, Argon2Config};
pub use keys::MasterKey;
pub use symmetric::Aes256Gcm;
pub use keys::generate_salt;

use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Failure during key derivation (e.g., Argon2 error).
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),
    
    /// Failure during the encryption process.
    #[error("Encryption failed: {0}")]
    Encryption(String),
    
    /// Failure during the decryption process (e.g., authentication tag mismatch).
    #[error("Decryption failed: {0}")]
    Decryption(String),
    
    /// The provided key is invalid for the requested operation.
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    
    /// Failure to generate random numbers for nonces or salts.
    #[error("Random number generation failed: {0}")]
    RandomError(String),
}

/// A structure representing encrypted data, including the necessary metadata for decryption.
/// 
/// This follows the standard practice of storing the nonce alongside the ciphertext.
#[derive(Debug, Clone)]
pub struct EncryptedData {
    /// A unique number used only once (Nonce/IV) for this encryption.
    /// In AES-GCM, this is typically 12 bytes.
    pub nonce: Vec<u8>,
    /// The actual encrypted message, including the authentication tag at the end.
    pub ciphertext: Vec<u8>,
}

impl EncryptedData {
    /// Creates a new `EncryptedData` instance.
    pub fn new(nonce: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }
    
    /// Encodes the encrypted data into a single base64 string for easy storage or transmission.
    /// The format is "base64_nonce:base64_ciphertext".
    pub fn to_base64(&self) -> String {
        use base64::Engine as _;
        let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(&self.nonce);
        let ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(&self.ciphertext);
        format!("{}:{}", nonce_b64, ciphertext_b64)
    }
    
    /// Decodes a "base64_nonce:base64_ciphertext" string back into an `EncryptedData` structure.
    pub fn from_base64(encoded: &str) -> Result<Self, CryptoError> {
        use base64::Engine as _;
        let parts: Vec<&str> = encoded.split(':').collect();
        if parts.len() != 2 {
            return Err(CryptoError::Decryption("Invalid format".to_string()));
        }
        
        let nonce = base64::engine::general_purpose::STANDARD
            .decode(parts[0])
            .map_err(|e| CryptoError::Decryption(e.to_string()))?;
        
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(parts[1])
            .map_err(|e| CryptoError::Decryption(e.to_string()))?;
        
        Ok(Self::new(nonce, ciphertext))
    }
}

use zeroize::Zeroize;

/// A wrapper for the 256-bit key used for vault encryption and decryption.
/// 
/// This struct implements `Zeroize`, ensuring that the sensitive key material is
/// wiped from memory when the object is dropped.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct VaultKey([u8; 32]);

impl VaultKey {
    /// Creates a `VaultKey` from 32 raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    
    /// Provides access to the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A wrapper for the 256-bit key used for Message Authentication Codes (MAC).
/// 
/// This struct implements `Zeroize`, ensuring that the sensitive key material is
/// wiped from memory when the object is dropped.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct MacKey([u8; 32]);

impl MacKey {
    /// Creates a `MacKey` from 32 raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    
    /// Provides access to the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
