//! Symmetric Encryption Module
//! 
//! AES-256-GCM implementation

use super::{CryptoError, EncryptedData, VaultKey};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm as AesGcm, Nonce,
};
use rand::RngCore;

/// An implementation of AES-256 in Galois/Counter Mode (GCM).
/// 
/// GCM is an "Authenticated Encryption" mode, meaning it provides both
/// confidentiality (hiding the data) and authenticity (verifying it hasn't changed).
pub struct Aes256Gcm {
    /// The underlying hardware-accelerated or software implementation of AES-GCM.
    cipher: AesGcm,
}

impl Aes256Gcm {
    /// Initializes a new AES-256-GCM cipher using the provided vault key.
    /// 
    /// # Parameters
    /// - `key`: The 256-bit key used for encryption and decryption.
    pub fn new(key: &VaultKey) -> Self {
        let cipher = AesGcm::new_from_slice(key.as_bytes())
            .expect("Invalid key length");
        Self { cipher }
    }
    
    /// Encrypts the given plaintext and optionally binds it to additional authenticated data (AAD).
    /// 
    /// # Parameters
    /// - `plaintext`: The secret data to be encrypted.
    /// - `aad`: Publicly visible data that should be protected against tampering, but not hidden.
    /// 
    /// # Returns
    /// - `Ok(EncryptedData)` containing a random nonce and the ciphertext.
    pub fn encrypt(&self, plaintext: &[u8], aad: Option<&[u8]>) -> Result<EncryptedData, CryptoError> {
        // Generate a unique 12-byte nonce for this specific encryption operation.
        // It is CRITICAL that a nonce is never reused with the same key.
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
    
    /// Decrypts the given `EncryptedData` and verifies its integrity.
    /// 
    /// # Parameters
    /// - `encrypted`: The nonce and ciphertext to decrypt.
    /// - `aad`: The same additional authenticated data used during encryption.
    /// 
    /// # Returns
    /// - `Ok(Vec<u8>)` containing the original plaintext if decryption and verification succeed.
    /// - `Err(CryptoError)` if the data was tampered with or the wrong key was used.
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encrypt_decrypt() {
        let key = VaultKey::from_bytes([0u8; 32]);
        let cipher = Aes256Gcm::new(&key);
        let data = b"hello world";
        
        let encrypted = cipher.encrypt(data, None).unwrap();
        let decrypted = cipher.decrypt(&encrypted, None).unwrap();
        
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encrypt_decrypt_with_aad() {
        let key = VaultKey::from_bytes([0u8; 32]);
        let cipher = Aes256Gcm::new(&key);
        let data = b"hello world";
        let aad = b"context-data";
        
        let encrypted = cipher.encrypt(data, Some(aad)).unwrap();
        let decrypted = cipher.decrypt(&encrypted, Some(aad)).unwrap();
        
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_decrypt_wrong_aad_fail() {
        let key = VaultKey::from_bytes([0u8; 32]);
        let cipher = Aes256Gcm::new(&key);
        let data = b"hello world";
        let aad1 = b"correct-aad";
        let aad2 = b"wrong-aad";
        
        let encrypted = cipher.encrypt(data, Some(aad1)).unwrap();
        let result = cipher.decrypt(&encrypted, Some(aad2));
        
        assert!(result.is_err());
    }
}

