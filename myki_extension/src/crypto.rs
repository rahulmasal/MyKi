//! Cryptographic operations for Myki Extension
//! Implements AES-256-GCM encryption with Argon2id key derivation for high security.

#![allow(dead_code)]

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors that can occur during cryptographic operations.
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

/// A wrapper around the master key derived from the user's password.
///
/// This key is used for all symmetric encryption (AES-256-GCM) within the vault.
/// It is never stored directly; only a hash of it is stored for verification.
pub struct MasterKey {
    /// The actual 32-byte key used for encryption.
    key: [u8; 32],
    /// The 16-byte salt used during the Argon2id derivation.
    salt: [u8; 16],
}

impl MasterKey {
    /// Derives a master key from a plaintext password using the Argon2id algorithm.
    ///
    /// Argon2id is used to protect against brute-force and rainbow table attacks
    /// by being memory-hard and time-consuming.
    ///
    /// # Arguments
    /// * `password` - The user's master password.
    /// * `salt` - An optional 16-byte salt. If None, a new random salt is generated.
    pub fn derive(password: &str, salt: Option<[u8; 16]>) -> Result<Self, CryptoError> {
        // Use provided salt or generate a fresh one from a secure random number generator (OsRng)
        let salt = salt.unwrap_or_else(|| {
            let mut s = [0u8; 16];
            OsRng.fill_bytes(&mut s);
            s
        });

        // Encode salt to base64 for Argon2
        let salt_string = SaltString::encode_b64(&salt)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        // Initialize Argon2id with default secure parameters
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt_string)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        // Extract the raw bytes from the Argon2 hash to use as our 256-bit AES key
        let hash_bytes = hash.hash.ok_or(CryptoError::KeyDerivationFailed)?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash_bytes.as_bytes()[..32]);

        Ok(Self { key, salt })
    }

    /// Returns the raw 32-byte key.
    pub fn as_bytes(&self) -> [u8; 32] {
        self.key
    }

    /// Returns the 16-byte salt.
    pub fn salt(&self) -> [u8; 16] {
        self.salt
    }

    /// Reconstructs a MasterKey from existing bytes.
    ///
    /// Used when loading a previously derived key from memory or during tests.
    pub fn from_existing(key: [u8; 32], salt: [u8; 16]) -> Self {
        Self { key, salt }
    }
}

/// Encrypts data using AES-256-GCM.
///
/// AES-256-GCM provides both confidentiality and integrity (it's "Authenticated Encryption").
///
/// # Arguments
/// * `plaintext` - The raw data to encrypt.
/// * `key` - The 32-byte (256-bit) master key.
///
/// # Returns
/// * `Vec<u8>` - The combined nonce (12 bytes) and ciphertext.
pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    // Initialize the AES-GCM cipher
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKey)?;

    // Generate a random 12-byte nonce (Number used once)
    // Security: Nonces MUST be unique for every encryption with the same key.
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Perform encryption
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    // Store the nonce at the beginning of the result so it can be retrieved for decryption
    let mut result = nonce_bytes.to_vec();
    result.extend(ciphertext);

    Ok(result)
}

/// Decrypts data using AES-256-GCM.
///
/// # Arguments
/// * `ciphertext` - The data to decrypt (must contain the 12-byte nonce at the start).
/// * `key` - The 32-byte (256-bit) master key.
pub fn decrypt(ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    // Ensure we have at least 12 bytes for the nonce
    if ciphertext.len() < 12 {
        return Err(CryptoError::InvalidData);
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CryptoError::InvalidKey)?;

    // Extract the 12-byte nonce from the start of the data
    let nonce = Nonce::from_slice(&ciphertext[..12]);
    let encrypted = &ciphertext[12..];

    // Perform decryption and integrity check
    cipher
        .decrypt(nonce, encrypted)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Computes a SHA-256 hash of the input data.
///
/// Used for password verification and fingerprinting.
pub fn hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Generates a cryptographically secure random password.
///
/// # Arguments
/// * `length` - Number of characters.
/// * `include_uppercase` - Use A-Z.
/// * `include_lowercase` - Use a-z.
/// * `include_numbers` - Use 0-9.
/// * `include_symbols` - Use special characters.
pub fn generate_password(
    length: usize,
    include_uppercase: bool,
    include_lowercase: bool,
    include_numbers: bool,
    include_symbols: bool,
) -> String {
    let mut charset = String::new();
    
    // Build the set of allowed characters
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
    
    // Fallback if no options selected
    if charset.is_empty() {
        charset = "abcdefghijklmnopqrstuvwxyz".to_string();
    }
    
    let charset_bytes: Vec<char> = charset.chars().collect();
    let mut password = String::with_capacity(length);
    
    // Generate secure random indices into the charset
    let mut random_bytes = [0u8; 64];
    OsRng.fill_bytes(&mut random_bytes);
    
    for item in random_bytes.iter().take(length) {
        let idx = *item as usize % charset_bytes.len();
        password.push(charset_bytes[idx]);
    }
    
    password
}

/// Verifies if a password is correct by deriving the key and comparing hashes.
///
/// # Arguments
/// * `password` - The attempt password.
/// * `salt` - The salt used when the vault was created.
/// * `stored_hash` - The SHA-256 hash of the correct master key.
pub fn verify_password(password: &str, salt: &[u8; 16], stored_hash: &[u8; 32]) -> bool {
    // Re-derive the key with the attempt password and same salt
    let derived = MasterKey::derive(password, Some(*salt)).ok();
    
    match derived {
        Some(key) => {
            // Hash the resulting key and compare to the stored one
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
