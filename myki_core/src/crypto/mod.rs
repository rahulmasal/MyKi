//! Cryptographic Module
//! 
//! This module provides the core cryptographic primitives used by Myki for secure
//! password management. It implements industry-standard algorithms for key derivation
//! and authenticated encryption.
//! 
//! # Security Properties
//! 
//! - **Key Derivation**: Argon2id provides resistance against GPU/ASIC attacks
//! - **Encryption**: AES-256-GCM provides confidentiality + integrity
//! - **Memory Safety**: Keys are wiped from memory when dropped (Zeroize)
//! 
//! # Module Structure
//! 
//! - `kdf.rs` - Key Derivation Function (Argon2id)
//! - `keys.rs` - Key types (MasterKey, VaultKey, MacKey)  
//! - `symmetric.rs` - AES-256-GCM encryption implementation

// ---------------------------------------------------------------------------
// Sub-module Declarations
// ---------------------------------------------------------------------------

// Key Derivation Function using Argon2id
pub mod kdf;

// Key types and key generation utilities
pub mod keys;

// AES-256-GCM symmetric encryption
pub mod symmetric;

// ---------------------------------------------------------------------------
// Re-exports for Public API
// ---------------------------------------------------------------------------
// These items are the main public interface of the crypto module

// Key derivation function and configuration
pub use kdf::{
    derive_key,     // Main KDF function: password + salt -> MasterKey
    KdfConfig,      // Wrapper for Argon2Config (trait-based API)
    Argon2Config,   // Argon2id parameters (memory, iterations, etc.)
};

// MasterKey is the root key type
pub use keys::MasterKey;

// AES-256-GCM cipher implementation
pub use symmetric::Aes256Gcm;

// Salt generation for key derivation
pub use keys::generate_salt;

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

// Import thiserror for clean error handling with derive macro
use thiserror::Error;

/// Errors that can occur during cryptographic operations.
/// 
/// These errors represent various failure modes in the crypto subsystem:
/// - Key derivation failures (invalid parameters, hardware issues)
/// - Encryption failures (invalid key length, etc.)
/// - Decryption failures (tampered data, wrong key)
/// - Random number generation failures (system RNG issues)
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Failure during key derivation (e.g., Argon2 error).
    /// The string contains details about what went wrong.
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),
    
    /// Failure during the encryption process.
    /// This is typically an internal error; check parameters.
    #[error("Encryption failed: {0}")]
    Encryption(String),
    
    /// Failure during the decryption process.
    /// This can indicate:
    /// - Wrong key used
    /// - Ciphertext was tampered with
    /// - Authentication tag mismatch
    #[error("Decryption failed: {0}")]
    Decryption(String),
    
    /// The provided key is invalid for the requested operation.
    /// Common causes:
    /// - Wrong length (AES-256 requires 32 bytes)
    /// - Malformed key data
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    
    /// Failure to generate random numbers for nonces or salts.
    /// This indicates a system-level RNG failure.
    #[error("Random number generation failed: {0}")]
    RandomError(String),
}

// ---------------------------------------------------------------------------
// Encrypted Data Type
// ---------------------------------------------------------------------------

/// A structure representing encrypted data, including the necessary metadata for decryption.
/// 
/// In AES-GCM mode, encryption produces two pieces of data:
/// 1. A random nonce (12 bytes) - unique per encryption
/// 2. The ciphertext + authentication tag
/// 
/// This struct holds both so they can be stored/transmitted together.
/// 
/// # Storage Format
/// 
/// The `to_base64()` method encodes this as "base64(nonce):base64(ciphertext)"
/// which is a compact, self-contained representation suitable for databases or files.
/// 
/// # Example
/// 
/// ```rust
/// use myki_core::{Aes256Gcm, VaultKey, EncryptedData};
/// 
/// let key = VaultKey::from_bytes([0u8; 32]);
/// let cipher = Aes256Gcm::new(&key);
/// 
/// let encrypted = cipher.encrypt(b"secret", None).unwrap();
/// let encoded = encrypted.to_base64();
/// 
/// // Later, decode and decrypt
/// let parsed = EncryptedData::from_base64(&encoded).unwrap();
/// let decrypted = cipher.decrypt(&parsed, None).unwrap();
/// ```
#[derive(Debug, Clone)]  // Debug and Clone for convenience; data is just bytes
pub struct EncryptedData {
    /// A unique number used only once (Nonce/IV) for this encryption.
    /// 
    /// The nonce is 12 bytes and is randomly generated for each encryption.
    /// It is NOT secret but MUST be unique per key - never reuse nonces.
    /// In AES-GCM, the nonce is prepended to the ciphertext internally.
    pub nonce: Vec<u8>,
    
    /// The actual encrypted message, including the authentication tag at the end.
    /// 
    /// The tag (16 bytes) is automatically appended by AES-GCM during encryption.
    /// During decryption, AES-GCM verifies the tag; if it doesn't match,
    /// decryption fails with an error.
    pub ciphertext: Vec<u8>,
}

impl EncryptedData {
    /// Creates a new `EncryptedData` instance from a nonce and ciphertext.
    /// 
    /// # Parameters
    /// 
    /// * `nonce`: The 12-byte nonce used during encryption
    /// * `ciphertext`: The encrypted data including the 16-byte auth tag
    pub fn new(nonce: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }
    
    /// Encodes the encrypted data into a single base64 string for easy storage or transmission.
    /// 
    /// The format is: "base64_nonce:base64_ciphertext"
    /// 
    /// This is suitable for storing in text-based formats like JSON, SQLite text columns,
    /// or environment variables.
    /// 
    /// # Returns
    /// 
    /// A single-line string like: "abcdef123456:/base64encodeddata=="
    pub fn to_base64(&self) -> String {
        use base64::Engine as _;
        
        // Encode nonce as base64 (12 bytes -> ~16 characters)
        let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(&self.nonce);
        
        // Encode ciphertext as base64
        let ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(&self.ciphertext);
        
        // Combine with colon separator
        format!("{}:{}", nonce_b64, ciphertext_b64)
    }
    
    /// Decodes a "base64_nonce:base64_ciphertext" string back into an `EncryptedData` structure.
    /// 
    /// This reverses `to_base64()`. The input must be properly formatted with exactly one colon.
    /// 
    /// # Parameters
    /// 
    /// * `encoded`: The base64-encoded string from `to_base64()`
    /// 
    /// # Returns
    /// 
    /// * `Ok(EncryptedData)` if decoding succeeded
    /// * `Err(CryptoError)` if the format is invalid or base64 decoding fails
    pub fn from_base64(encoded: &str) -> Result<Self, CryptoError> {
        use base64::Engine as _;
        
        // Split on the colon separator
        let parts: Vec<&str> = encoded.split(':').collect();
        
        // Must have exactly 2 parts
        if parts.len() != 2 {
            return Err(CryptoError::Decryption("Invalid format: expected 'nonce:ciphertext'".to_string()));
        }
        
        // Decode the nonce
        let nonce = base64::engine::general_purpose::STANDARD
            .decode(parts[0])
            .map_err(|e| CryptoError::Decryption(format!("Invalid nonce base64: {}", e)))?;
        
        // Decode the ciphertext
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(parts[1])
            .map_err(|e| CryptoError::Decryption(format!("Invalid ciphertext base64: {}", e)))?;
        
        Ok(Self::new(nonce, ciphertext))
    }
}

// ---------------------------------------------------------------------------
// Key Type Wrappers
// ---------------------------------------------------------------------------

// Zeroize ensures sensitive data is wiped from memory when dropped
use zeroize::Zeroize;

/// A wrapper for the 256-bit key used for vault encryption and decryption.
/// 
/// VaultKey wraps a 32-byte array containing the actual key material.
/// The `Zeroize` derive ensures that when this struct is dropped, the key
/// bytes are overwritten with zeros, preventing sensitive data from lingering
/// in memory.
/// 
/// # Why a wrapper type?
/// 
/// Using a wrapper type (rather than raw `[u8; 32]`) provides:
/// 1. Type safety - prevents accidentally passing wrong-length keys
/// 2. Semantic meaning - distinguishes encryption keys from other data
/// 3. Zeroize trait - automatic secure memory cleanup
/// 
/// # Example
/// 
/// ```rust
/// use myki_core::{VaultKey, Aes256Gcm};
/// 
/// // Create from raw bytes
/// let key_bytes = [0x42u8; 32];
/// let vault_key = VaultKey::from_bytes(key_bytes);
/// 
/// // Use with cipher
/// let cipher = Aes256Gcm::new(&vault_key);
/// ```
#[derive(Zeroize)]  // Wipe memory on drop - critical for security!
#[zeroize(drop)]     // Automatically call zeroize() when this struct is dropped
pub struct VaultKey([u8; 32]);  // Private inner array - exposure controlled via methods

impl VaultKey {
    /// Creates a `VaultKey` from 32 raw bytes.
    /// 
    /// # Parameters
    /// 
    /// * `bytes`: An array of exactly 32 bytes
    /// 
    /// # Panics
    /// 
    /// This function can panic if the input array is not exactly 32 bytes
    /// (though the type system should prevent this).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    
    /// Provides read-only access to the raw key bytes.
    /// 
    /// This returns a reference to the inner array, allowing the cipher
    /// to access the key material without cloning.
    /// 
    /// # Returns
    /// 
    /// A reference to the 32-byte key array
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Base64 Utility Functions
// ---------------------------------------------------------------------------

/// Encodes a byte slice into a base64 string.
/// 
/// This is a convenience function for encoding arbitrary binary data.
/// 
/// # Parameters
/// 
/// * `data`: The bytes to encode
/// 
/// # Returns
/// 
/// A base64-encoded string using the standard alphabet
pub fn encode_base64(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Decodes a base64 string into a byte vector.
/// 
/// # Parameters
/// 
/// * `encoded`: The base64 string to decode
/// 
/// # Returns
/// 
/// * `Ok(Vec<u8>)` if decoding succeeded
/// * `Err(CryptoError)` if the string is not valid base64
pub fn decode_base64(encoded: &str) -> Result<Vec<u8>, CryptoError> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(encoded)
        .map_err(|e| CryptoError::Decryption(e.to_string()))
}

// ---------------------------------------------------------------------------
// MAC Key Type
// ---------------------------------------------------------------------------

/// A wrapper for the 256-bit key used for Message Authentication Codes (MAC).
/// 
/// MAC keys are used to generate authentication tags for data integrity.
/// In Myki's current implementation, MAC keys are derived but not yet
/// actively used (the AES-GCM cipher handles integrity internally).
/// 
/// This type exists for forward compatibility and to maintain the
/// separation of concerns established by the Argon2id key derivation.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct MacKey([u8; 32]);

impl MacKey {
    /// Creates a `MacKey` from 32 raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    
    /// Provides read-only access to the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
