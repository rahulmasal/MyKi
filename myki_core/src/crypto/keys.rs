//! Key Management Module
//! 
//! Master key and derived keys

use crate::crypto::{VaultKey, MacKey};
use rand::RngCore;

/// The root key for the entire vault, from which other specialized keys are derived.
/// 
/// In a password manager, the master key is derived from the user's master password.
/// It is then split into separate keys for encryption and integrity to follow
/// cryptographic best practices.
pub struct MasterKey {
    /// The key used to encrypt and decrypt the actual data (AES-256).
    pub vault_key: VaultKey,
    /// The key used to ensure the data hasn't been tampered with (MAC).
    pub mac_key: MacKey,
}

impl MasterKey {
    /// Creates a `MasterKey` by splitting 64 bytes of derived material into 
    /// two 32-byte keys.
    /// 
    /// # Parameters
    /// - `derived`: 64 bytes of raw key material (e.g., from Argon2id).
    pub fn from_derived(derived: [u8; 64]) -> Self {
        let mut vault_bytes = [0u8; 32];
        let mut mac_bytes = [0u8; 32];
        
        // The first 32 bytes are for encryption
        vault_bytes.copy_from_slice(&derived[0..32]);
        // The remaining 32 bytes are for integrity
        mac_bytes.copy_from_slice(&derived[32..64]);
        
        Self {
            vault_key: VaultKey::from_bytes(vault_bytes),
            mac_key: MacKey::from_bytes(mac_bytes),
        }
    }
}

/// Generates a unique, random 32-byte salt using a cryptographically secure 
/// random number generator (CSPRNG).
/// 
/// A salt is used during key derivation to ensure that even if two users have
/// the same password, their derived keys will be completely different.
pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

/// Generate a random master key (for testing)
#[cfg(test)]
pub fn generate_random_key() -> MasterKey {
    let mut vault_bytes = [0u8; 32];
    let mut mac_bytes = [0u8; 32];
    
    rand::rngs::OsRng.fill_bytes(&mut vault_bytes);
    rand::rngs::OsRng.fill_bytes(&mut mac_bytes);
    
    MasterKey {
        vault_key: VaultKey::from_bytes(vault_bytes),
        mac_key: MacKey::from_bytes(mac_bytes),
    }
}
