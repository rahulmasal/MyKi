//! Symmetric Encryption Module
//! 
//! This module implements AES-256-GCM (Advanced Encryption Standard in Galois/Counter Mode),
//! which provides authenticated encryption - both confidentiality and integrity in one algorithm.
//! 
//! # What is AES-256-GCM?
//! 
//! ```
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    AES-256-GCM                             │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                             │
//! │   Plaintext ──► AES-256 ──► Ciphertext                    │
//! │                    │                                       │
//! │                    │                                       │
//! │               ┌────┴────┐                                 │
//! │               │ 12-byte │                                 │
//! │               │  Nonce  │                                 │
//! │               └─────────┘                                 │
//! │                                                             │
//! │   Output: nonce || ciphertext || auth_tag (16 bytes)        │
//! │                                                             │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//! 
//! # Why GCM?
//! 
//! - **Authenticated Encryption**: Provides both confidentiality AND integrity
//! - **Parallelizable**: Efficient on modern multi-core processors
//! - **Provably Secure**: Under strong security definitions when used correctly
//! - **No Padding Oracle**: Unlike CBC mode, not vulnerable to padding attacks
//! 
//! # Security Notes
//! 
//! 1. **Never reuse nonces**: Each encryption must use a unique 12-byte nonce
//! 2. **Key security**: The 256-bit key must remain secret
//! 3. **Tag verification**: Decryption will fail if ciphertext is tampered with

use super::{CryptoError, EncryptedData, VaultKey};  // Import types from parent module
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},  // Traits for AEAD ciphers: Aead (encrypt/decrypt), KeyInit (key setup), OsRng (random)
    Aes256Gcm as AesGcm,            // The actual AES-GCM implementation (renamed to avoid conflict)
    Nonce,                          // The 12-byte nonce type
};
use rand::RngCore;  // For generating random nonces

// ---------------------------------------------------------------------------
// AES-256-GCM Cipher Implementation
// ---------------------------------------------------------------------------

/// An implementation of AES-256 in Galois/Counter Mode (GCM).
/// 
/// AES-256-GCM is an authenticated encryption algorithm that provides:
/// - **Confidentiality**: Only authorized parties can read the plaintext
/// - **Integrity**: Tampering with the ciphertext is detected
/// - **Authentication**: The origin of the data can be verified
/// 
/// # Initialization
/// 
/// Create a cipher instance with a 256-bit (32-byte) key:
/// 
/// ```rust
/// use myki_core::{Aes256Gcm, VaultKey};
/// 
/// let key = VaultKey::from_bytes([0u8; 32]);
/// let cipher = Aes256Gcm::new(&key);
/// ```
/// 
/// # Usage
/// 
/// ```rust
/// // Encrypt
/// let encrypted = cipher.encrypt(b"secret message", None).unwrap();
///
/// // Decrypt
/// let decrypted = cipher.decrypt(&encrypted, None).unwrap();
/// ```
pub struct Aes256Gcm {
    /// The underlying AES-GCM cipher implementation.
    /// 
    /// This is either a hardware-accelerated implementation (AES-NI on modern x86)
    /// or a software fallback. Either way, the interface is the same.
    /// 
    /// The `aes_gcm::Aes256Gcm` type is a wrapper around the low-level
    /// AES implementation with GCM mode built-in.
    cipher: AesGcm,
}

impl Aes256Gcm {
    /// Initializes a new AES-256-GCM cipher using the provided vault key.
    /// 
    /// # Parameters
    /// 
    /// * `key`: A reference to a 256-bit VaultKey for encryption/decryption
    /// 
    /// # Panics
    /// 
    /// This function will panic if the key is not exactly 32 bytes.
    /// However, since we use VaultKey which enforces this, it should never happen.
    pub fn new(key: &VaultKey) -> Self {
        // Aes256Gcm::new_from_slice creates a cipher instance from raw key bytes
        // The KeyInit trait provides this method
        // expect() will panic only if key length is wrong (32 bytes required)
        let cipher = AesGcm::new_from_slice(key.as_bytes())
            .expect("Invalid key length: AES-256 requires exactly 32 bytes");
        
        Self { cipher }
    }
    
    /// Encrypts the given plaintext and optionally binds it to additional authenticated data (AAD).
    /// 
    /// This method generates a fresh random nonce for each encryption, which is critical
    /// for security. The nonce is prepended to the output and must be used for decryption.
    /// 
    /// # Parameters
    /// 
    /// * `plaintext`: The secret data to be encrypted. Can be any bytes (UTF-8, binary, etc.)
    /// 
    /// * `aad`: Optional Additional Authenticated Data.
    ///   This is data that is authenticated but NOT encrypted (e.g., a header, sequence number).
    ///   If provided during encryption, it MUST be provided during decryption, or verification fails.
    ///   Pass `None` if you don't need AAD.
    /// 
    /// # Returns
    /// 
    /// * `Ok(EncryptedData)` containing:
    ///   - `nonce`: A unique 12-byte random value (generated fresh each time)
    ///   - `ciphertext`: The encrypted data including the 16-byte authentication tag
    /// * `Err(CryptoError)` if encryption fails (should not happen with valid inputs)
    /// 
    /// # Example
    /// 
    /// ```rust
    /// use myki_core::{Aes256Gcm, VaultKey};
    /// 
    /// let key = VaultKey::from_bytes([0u8; 32]);
    /// let cipher = Aes256Gcm::new(&key);
    /// 
    /// // Simple encryption
    /// let encrypted = cipher.encrypt(b"password123", None).unwrap();
    /// 
    /// // Encryption with AAD (authenticated but not encrypted)
    /// let encrypted_with_aad = cipher.encrypt(b"data", Some(b"context")).unwrap();
    /// ```
    /// 
    /// # Security Notes
    /// 
    /// - A fresh nonce is generated for EVERY encryption (uses OsRng)
    /// - Never use the same key with the same nonce twice
    /// - The nonce is NOT secret (it's stored with the ciphertext)
    pub fn encrypt(&self, plaintext: &[u8], aad: Option<&[u8]>) -> Result<EncryptedData, CryptoError> {
        // -----------------------------------------------------------------------
        // Generate a unique 12-byte nonce
        // -----------------------------------------------------------------------
        // The nonce (Number used once) is critical for security:
        // - Must be unique per key (never reuse)
        // - Should be unpredictable (random is fine)
        // - 12 bytes is the standard length for GCM
        // 
        // OsRng is the operating system's cryptographically secure RNG
        
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // -----------------------------------------------------------------------
        // Prepare the payload with optional AAD
        // -----------------------------------------------------------------------
        // The Payload struct holds both the message and any Additional Authenticated Data.
        // AAD is useful when you have metadata that should be authenticated but not encrypted.
        // Example: encrypted packet with unencrypted header that must not be modified
        
        let payload = if let Some(aad_data) = aad {
            // Create payload with AAD (authenticated but not encrypted)
            aes_gcm::aead::Payload { msg: plaintext, aad: aad_data }
        } else {
            // Create payload without AAD
            aes_gcm::aead::Payload { msg: plaintext, aad: &[] }
        };

        // -----------------------------------------------------------------------
        // Encrypt the data
        // -----------------------------------------------------------------------
        // encrypt() takes the nonce and payload, returns the ciphertext with auth tag
        // The authentication tag is automatically appended to the ciphertext
        let ciphertext = self.cipher
            .encrypt(nonce, payload)
            .map_err(|e| CryptoError::Encryption(format!("Encryption failed: {}", e)))?;

        // Return the encrypted data (nonce is included for use during decryption)
        Ok(EncryptedData::new(nonce_bytes.to_vec(), ciphertext))
    }
    
    /// Decrypts the given `EncryptedData` and verifies its integrity.
    /// 
    /// This method:
    /// 1. Extracts the nonce from the encrypted data
    /// 2. Verifies the authentication tag (integrity check)
    /// 3. Decrypts the ciphertext using AES-256-GCM in reverse
    /// 
    /// If the ciphertext has been tampered with OR the wrong key is used,
    /// this function will return an error.
    /// 
    /// # Parameters
    /// 
    /// * `encrypted`: The encrypted data containing nonce and ciphertext
    /// 
    /// * `aad`: The same additional authenticated data used during encryption.
    ///          If encryption used AAD, decryption MUST use the same AAD.
    ///          Pass `None` if encryption was done without AAD.
    /// 
    /// # Returns
    /// 
    /// * `Ok(Vec<u8>)` containing the original plaintext if:
    ///   - Authentication tag verified
    ///   - Decryption succeeded
    /// * `Err(CryptoError)` if:
    ///   - Wrong key used
    ///   - Ciphertext was tampered with
    ///   - AAD mismatch
    /// 
    /// # Example
    /// 
    /// ```rust
    /// use myki_core::{Aes256Gcm, VaultKey};
    /// 
    /// let key = VaultKey::from_bytes([0u8; 32]);
    /// let cipher = Aes256Gcm::new(&key);
    /// 
    /// // Encrypt
    /// let encrypted = cipher.encrypt(b"secret", None).unwrap();
    /// 
    /// // Decrypt - returns original bytes
    /// let decrypted = cipher.decrypt(&encrypted, None).unwrap();
    /// assert_eq!(decrypted, b"secret");
    /// ```
    pub fn decrypt(&self, encrypted: &EncryptedData, aad: Option<&[u8]>) -> Result<Vec<u8>, CryptoError> {
        // -----------------------------------------------------------------------
        // Extract the nonce
        // -----------------------------------------------------------------------
        // Nonce::from_slice creates a view into the encrypted.nonce bytes
        // This doesn't copy data, just creates a reference with the correct type
        let nonce = Nonce::from_slice(&encrypted.nonce);

        // -----------------------------------------------------------------------
        // Prepare payload with optional AAD
        // -----------------------------------------------------------------------
        // Must use the SAME AAD that was used during encryption
        let payload = if let Some(aad_data) = aad {
            aes_gcm::aead::Payload { msg: &encrypted.ciphertext, aad: aad_data }
        } else {
            aes_gcm::aead::Payload { msg: &encrypted.ciphertext, aad: &[] }
        };

        // -----------------------------------------------------------------------
        // Decrypt and verify
        // -----------------------------------------------------------------------
        // decrypt() performs two operations atomically:
        // 1. Verify the authentication tag (integrity)
        // 2. Decrypt the ciphertext if verification succeeds
        // 
        // If verification fails (tampered data), an error is returned
        // BEFORE any plaintext is returned - no partial decryption happens
        self.cipher
            .decrypt(nonce, payload)
            .map_err(|e| CryptoError::Decryption(format!("Decryption or verification failed: {}", e)))
    }
}

// ---------------------------------------------------------------------------
// Trait for Generic AEAD Ciphers
// ---------------------------------------------------------------------------

/// A trait defining the interface for authenticated encryption ciphers.
/// 
/// This trait allows different cipher implementations (AES-GCM, ChaCha20-Poly1305, etc.)
/// to be used interchangeably. Currently, only Aes256Gcm implements this, but the
/// trait allows for future cipher options.
/// 
/// # Example Implementations
/// 
/// - Aes256Gcm: AES-256 in Galois/Counter Mode
/// - ChaCha20Poly1305: ChaCha20 stream cipher with Poly1305 authentication (future)
pub trait AeadCipher {
    /// Encrypts plaintext and returns encrypted data.
    fn encrypt(&self, plaintext: &[u8], aad: Option<&[u8]>) -> Result<EncryptedData, CryptoError>;
    
    /// Decrypts encrypted data and returns plaintext.
    fn decrypt(&self, encrypted: &EncryptedData, aad: Option<&[u8]>) -> Result<Vec<u8>, CryptoError>;
}

impl AeadCipher for Aes256Gcm {
    /// Encrypt using AES-256-GCM.
    fn encrypt(&self, plaintext: &[u8], aad: Option<&[u8]>) -> Result<EncryptedData, CryptoError> {
        Aes256Gcm::encrypt(self, plaintext, aad)
    }
    
    /// Decrypt using AES-256-GCM.
    fn decrypt(&self, encrypted: &EncryptedData, aad: Option<&[u8]>) -> Result<Vec<u8>, CryptoError> {
        Aes256Gcm::decrypt(self, encrypted, aad)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Test basic encrypt/decrypt roundtrip with no AAD.
    #[test]
    fn test_encrypt_decrypt() {
        // Use all-zeroes key for testing (NOT for production!)
        let key = VaultKey::from_bytes([0u8; 32]);
        let cipher = Aes256Gcm::new(&key);
        let data = b"hello world";
        
        // Encrypt
        let encrypted = cipher.encrypt(data, None).unwrap();
        
        // Verify nonce is 12 bytes
        assert_eq!(encrypted.nonce.len(), 12);
        
        // Verify ciphertext is different from plaintext
        assert_ne!(encrypted.ciphertext, data.as_slice());
        
        // Decrypt
        let decrypted = cipher.decrypt(&encrypted, None).unwrap();
        
        // Verify roundtrip
        assert_eq!(decrypted, data);
    }

    /// Test encrypt/decrypt with Additional Authenticated Data.
    #[test]
    fn test_encrypt_decrypt_with_aad() {
        let key = VaultKey::from_bytes([0u8; 32]);
        let cipher = Aes256Gcm::new(&key);
        let data = b"hello world";
        let aad = b"context-data";  // AAD is authenticated but not encrypted
        
        // Encrypt with AAD
        let encrypted = cipher.encrypt(data, Some(aad)).unwrap();
        
        // Decrypt with same AAD - should succeed
        let decrypted = cipher.decrypt(&encrypted, Some(aad)).unwrap();
        assert_eq!(decrypted, data);
        
        // Decrypt without AAD - should fail (AAD mismatch)
        let result = cipher.decrypt(&encrypted, None);
        assert!(result.is_err());
    }

    /// Test that wrong AAD causes decryption to fail (integrity check).
    #[test]
    fn test_decrypt_wrong_aad_fail() {
        let key = VaultKey::from_bytes([0u8; 32]);
        let cipher = Aes256Gcm::new(&key);
        let data = b"hello world";
        let aad1 = b"correct-aad";
        let aad2 = b"wrong-aad";
        
        // Encrypt with correct AAD
        let encrypted = cipher.encrypt(data, Some(aad1)).unwrap();
        
        // Try to decrypt with wrong AAD - should fail
        let result = cipher.decrypt(&encrypted, Some(aad2));
        assert!(result.is_err());
    }
}
