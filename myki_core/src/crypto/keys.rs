//! Key Management Module
//! 
//! Master key and derived keys

use crate::crypto::{VaultKey, MacKey};
use rand::RngCore;

/// Master key derived from password
pub struct MasterKey {
    /// Vault encryption key (32 bytes)
    pub vault_key: VaultKey,
    /// MAC key for integrity (32 bytes)
    pub mac_key: MacKey,
}

impl MasterKey {
    /// Create master key from derived bytes
    pub fn from_derived(derived: [u8; 64]) -> Self {
        let mut vault_bytes = [0u8; 32];
        let mut mac_bytes = [0u8; 32];
        
        vault_bytes.copy_from_slice(&derived[0..32]);
        mac_bytes.copy_from_slice(&derived[32..64]);
        
        Self {
            vault_key: VaultKey::from_bytes(vault_bytes),
            mac_key: MacKey::from_bytes(mac_bytes),
        }
    }
}

/// Generate a random salt
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
