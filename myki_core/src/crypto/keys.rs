//! Key Management Module
//! 
//! This module defines the key types used throughout Myki for cryptographic operations.
//! 
//! # Key Hierarchy
//! 
//! ```
//! Master Password
//!       │
//!       ▼
//!    Argon2id KDF
//!       │
//!       ▼
//!   MasterKey (64 bytes)
//!       │
//!       ├──► VaultKey (32 bytes) ──► AES-256-GCM Encryption
//!       │
//!       └──► MacKey (32 bytes) ──► Message Authentication (future)
//! ```
//! 
//! The split between VaultKey and MacKey follows cryptographic best practices:
//! Using the same key for multiple purposes can lead to vulnerabilities.

use crate::crypto::{VaultKey, MacKey};  // Import key wrapper types from parent module
use rand::RngCore;  // Random number generation for salt creation

// ---------------------------------------------------------------------------
// Master Key Type
// ---------------------------------------------------------------------------

/// The root key for the entire vault, from which other specialized keys are derived.
/// 
/// MasterKey is the top-level key type in Myki's key hierarchy. It's derived from
/// the user's master password using Argon2id, then split into two purpose-specific keys.
/// 
/// # Why Split the Key?
/// 
/// Cryptographic best practice is to use separate keys for different purposes:
/// 
/// 1. **VaultKey**: Used for AES-256-GCM encryption/decryption
/// 2. **MacKey**: Reserved for future message authentication operations
/// 
/// This separation provides:
/// - Better security margins (compromise of one doesn't affect the other)
/// - Future flexibility (can change MAC algorithm without re-encrypting)
/// - Clearer security proofs (each key has one purpose)
/// 
/// # Lifetime
/// 
/// MasterKey should only exist in memory during an active session.
/// It's never persisted to disk - only the salt and a hash of the derived key are stored.
pub struct MasterKey {
    /// The key used to encrypt and decrypt the actual data (AES-256).
    /// 
    /// This is the first 32 bytes of the Argon2id output.
    /// All vault data is encrypted with this key.
    pub vault_key: VaultKey,
    
    /// The key used to ensure the data hasn't been tampered with (MAC).
    /// 
    /// This is the second 32 bytes of the Argon2id output.
    /// Currently reserved for future use (AES-GCM handles authentication internally).
    pub mac_key: MacKey,
}

impl MasterKey {
    /// Creates a `MasterKey` by splitting 64 bytes of derived material into two 32-byte keys.
    /// 
    /// This function is called after Argon2id key derivation. The 64 bytes of derived
    /// material are split as follows:
    /// 
    /// - Bytes 0-31: VaultKey (for encryption)
    /// - Bytes 32-63: MacKey (for authentication)
    /// 
    /// # Parameters
    /// 
    /// * `derived`: 64 bytes of raw key material from Argon2id
    /// 
    /// # Example
    /// 
    /// ```rust
    /// use myki_core::MasterKey;
    /// 
    /// // After calling derive_key(), you get a MasterKey directly
    /// // This function is mainly for internal use or testing
    /// let derived = [0u8; 64];
    /// let master_key = MasterKey::from_derived(derived);
    /// ```
    pub fn from_derived(derived: [u8; 64]) -> Self {
        // Allocate buffers for the two 32-byte keys
        let mut vault_bytes = [0u8; 32];
        let mut mac_bytes = [0u8; 32];
        
        // Copy first 32 bytes to vault_key
        // copy_from_slice ensures we don't have uninitialized data
        vault_bytes.copy_from_slice(&derived[0..32]);
        
        // Copy second 32 bytes to mac_key
        mac_bytes.copy_from_slice(&derived[32..64]);
        
        Self {
            vault_key: VaultKey::from_bytes(vault_bytes),
            mac_key: MacKey::from_bytes(mac_bytes),
        }
    }
}

// ---------------------------------------------------------------------------
// Salt Generation
// ---------------------------------------------------------------------------

/// Generates a unique, random 32-byte salt using a cryptographically secure 
/// random number generator (CSPRNG).
/// 
/// A salt is a random value used as input to key derivation. It's stored alongside
/// the encrypted vault and used whenever the user unlocks their vault.
/// 
/// # Why Use a Salt?
/// 
/// Without a salt, two users with the same password would have the same derived key.
/// A salt ensures that even identical passwords produce completely different keys.
/// 
/// # Security Properties
/// 
/// - **Uniqueness**: Each vault should have its own salt
/// - **Randomness**: Must be generated from a CSPRNG (not math::Random)
/// - **Storage**: Salt is NOT secret, but should be stored with the vault
/// 
/// # Example
/// 
/// ```rust
/// use myki_core::crypto::generate_salt;
/// 
/// let salt = generate_salt();
/// // salt is [u8; 32] - store this with your vault metadata
/// ```
pub fn generate_salt() -> [u8; 32] {
    // Allocate buffer for 32 bytes
    let mut salt = [0u8; 32];
    
    // Fill with random bytes from the operating system's CSPRNG
    // OsRng is a cryptographically secure random number generator
    // that uses system APIs (getrandom on Linux, BCrypt on Windows, etc.)
    rand::rngs::OsRng.fill_bytes(&mut salt);
    
    salt
}

// ---------------------------------------------------------------------------
// Test Utilities
// ---------------------------------------------------------------------------

/// Generate a random master key for testing purposes only.
/// 
/// This function should NEVER be used in production code because:
/// - It doesn't derive from a password (no way to reproduce the key)
/// - It's only useful for testing the cipher implementation
#[cfg(test)]  // Only available during testing
pub fn generate_random_key() -> MasterKey {
    // Allocate buffers for both keys
    let mut vault_bytes = [0u8; 32];
    let mut mac_bytes = [0u8; 32];
    
    // Fill with random bytes
    // Note: In tests, we use OsRng which is still cryptographically secure
    // but we don't care about reproducibility
    rand::rngs::OsRng.fill_bytes(&mut vault_bytes);
    rand::rngs::OsRng.fill_bytes(&mut mac_bytes);
    
    MasterKey {
        vault_key: VaultKey::from_bytes(vault_bytes),
        mac_key: MacKey::from_bytes(mac_bytes),
    }
}
