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

/// Cryptographic errors
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),
    
    #[error("Encryption failed: {0}")]
    Encryption(String),
    
    #[error("Decryption failed: {0}")]
    Decryption(String),
    
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    
    #[error("Random number generation failed: {0}")]
    RandomError(String),
}

/// Encrypted data structure
#[derive(Debug, Clone)]
pub struct EncryptedData {
    /// Nonce/IV (12 bytes for AES-GCM)
    pub nonce: Vec<u8>,
    /// Ciphertext with authentication tag
    pub ciphertext: Vec<u8>,
}

impl EncryptedData {
    /// Create new encrypted data
    pub fn new(nonce: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }
    
    /// Encode to base64 string (nonce:ciphertext)
    pub fn to_base64(&self) -> String {
        use base64::Engine as _;
        let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(&self.nonce);
        let ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(&self.ciphertext);
        format!("{}:{}", nonce_b64, ciphertext_b64)
    }
    
    /// Decode from base64 string
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

/// Vault key wrapper
pub struct VaultKey([u8; 32]);

impl VaultKey {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    
    /// Get bytes reference
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// MAC key wrapper
pub struct MacKey([u8; 32]);

impl MacKey {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    
    /// Get bytes reference
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
