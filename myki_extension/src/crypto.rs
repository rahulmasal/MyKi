//! Cryptographic operations for Myki Extension
//! Implements AES-256-GCM encryption with Argon2id key derivation

#![allow(dead_code)]

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Key derivation failed")]
    KeyDerivationFailed,
    #[error("Invalid key")]
    InvalidKey,
    #[error("Invalid data")]
    InvalidData,
}

/// Master key derived from password
pub struct MasterKey {
    key: [u8; 32],
    salt: [u8; 16],
}

impl MasterKey {
    /// Derive master key from password using Argon2id
    pub fn derive(password: &str, salt: Option<[u8; 16]>) -> Result<Self, CryptoError> {
        let salt = salt.unwrap_or_else(|| {
            let mut s = [0u8; 16];
            OsRng.fill_bytes(&mut s);
            s
        });

        let salt_string = SaltString::encode_b64(&salt)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt_string)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        let hash_bytes = hash.hash.ok_or(CryptoError::KeyDerivationFailed)?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash_bytes.as_bytes()[..32]);

        Ok(Self { key, salt })
    }

    /// Get the derived key bytes
    pub fn as_bytes(&self) -> [u8; 32] {
        self.key
    }

    /// Get the salt
    pub fn salt(&self) -> [u8; 16] {
        self.salt
    }

    /// Create from existing key and salt (for loading from storage)
    pub fn from_existing(key: [u8; 32], salt: [u8; 16]) -> Self {
        Self { key, salt }
    }
}

/// Encrypt data using AES-256-GCM
pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKey)?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    // Prepend nonce to ciphertext
    let mut result = nonce_bytes.to_vec();
    result.extend(ciphertext);

    Ok(result)
}

/// Decrypt data using AES-256-GCM
pub fn decrypt(ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    if ciphertext.len() < 12 {
        return Err(CryptoError::InvalidData);
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKey)?;

    // Extract nonce and ciphertext
    let nonce = Nonce::from_slice(&ciphertext[..12]);
    let encrypted = &ciphertext[12..];

    // Decrypt
    cipher
        .decrypt(nonce, encrypted)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Compute SHA-256 hash
pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Generate a secure random password
pub fn generate_password(
    length: usize,
    include_uppercase: bool,
    include_lowercase: bool,
    include_numbers: bool,
    include_symbols: bool,
) -> String {
    let mut charset = String::new();
    
    if include_lowercase {
        charset.push_str("abcdefghijklmnopqrstuvwxyz");
    }
    if include_uppercase {
        charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if include_numbers {
        charset.push_str("0123456789");
    }
    if include_symbols {
        charset.push_str("!@#$%^&*()_+-=[]{}|;:,.<>?");
    }
    
    if charset.is_empty() {
        charset = "abcdefghijklmnopqrstuvwxyz".to_string();
    }
    
    let charset_bytes: Vec<char> = charset.chars().collect();
    let mut password = String::with_capacity(length);
    let mut random_bytes = [0u8; 64];
    OsRng.fill_bytes(&mut random_bytes);
    
    for item in random_bytes.iter().take(length) {
        let idx = *item as usize % charset_bytes.len();
        password.push(charset_bytes[idx]);
    }
    
    password
}

/// Verify password against stored hash
pub fn verify_password(password: &str, salt: &[u8; 16], stored_hash: &[u8; 32]) -> bool {
    let derived = MasterKey::derive(password, Some(*salt)).ok();
    
    match derived {
        Some(key) => {
            let computed_hash = hash(&key.as_bytes());
            computed_hash == *stored_hash
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = MasterKey::derive("test_password", None).unwrap();
        let plaintext = b"Hello, World!";
        
        let ciphertext = encrypt(plaintext, &key.as_bytes()).unwrap();
        let decrypted = decrypt(&ciphertext, &key.as_bytes()).unwrap();
        
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_generate_password() {
        let password = generate_password(16, true, true, true, true);
        assert_eq!(password.len(), 16);
    }
}
