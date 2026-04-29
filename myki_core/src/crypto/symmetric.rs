//! Symmetric Encryption Module
//! 
//! AES-256-GCM implementation

use super::{CryptoError, EncryptedData, VaultKey};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm as AesGcm, Nonce,
};
use rand::RngCore;

/// AES-256-GCM cipher
pub struct Aes256Gcm {
    cipher: AesGcm,
}

impl Aes256Gcm {
    /// Create new cipher with vault key
    pub fn new(key: &VaultKey) -> Self {
        let cipher = AesGcm::new_from_slice(key.as_bytes())
            .expect("Invalid key length");
        Self { cipher }
    }
    
    /// Encrypt data
    pub fn encrypt(&self, plaintext: &[u8], aad: Option<&[u8]>) -> Result<EncryptedData, CryptoError> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let payload = if let Some(aad_data) = aad {
            aes_gcm::aead::Payload { msg: plaintext, aad: aad_data }
        } else {
            aes_gcm::aead::Payload { msg: plaintext, aad: &[] }
        };

        let ciphertext = self.cipher
            .encrypt(nonce, payload)
            .map_err(|e| CryptoError::Encryption(e.to_string()))?;

        Ok(EncryptedData::new(nonce_bytes.to_vec(), ciphertext))
    }
    
    /// Decrypt data
    pub fn decrypt(&self, encrypted: &EncryptedData, aad: Option<&[u8]>) -> Result<Vec<u8>, CryptoError> {
        let nonce = Nonce::from_slice(&encrypted.nonce);

        let payload = if let Some(aad_data) = aad {
            aes_gcm::aead::Payload { msg: &encrypted.ciphertext, aad: aad_data }
        } else {
            aes_gcm::aead::Payload { msg: &encrypted.ciphertext, aad: &[] }
        };

        self.cipher
            .decrypt(nonce, payload)
            .map_err(|e| CryptoError::Decryption(e.to_string()))
    }
}

/// Trait for AEAD ciphers
pub trait AeadCipher {
    fn encrypt(&self, plaintext: &[u8], aad: Option<&[u8]>) -> Result<EncryptedData, CryptoError>;
    fn decrypt(&self, encrypted: &EncryptedData, aad: Option<&[u8]>) -> Result<Vec<u8>, CryptoError>;
}

impl AeadCipher for Aes256Gcm {
    fn encrypt(&self, plaintext: &[u8], aad: Option<&[u8]>) -> Result<EncryptedData, CryptoError> {
        Aes256Gcm::encrypt(self, plaintext, aad)
    }
    
    fn decrypt(&self, encrypted: &EncryptedData, aad: Option<&[u8]>) -> Result<Vec<u8>, CryptoError> {
        Aes256Gcm::decrypt(self, encrypted, aad)
    }
}
