//! Key Derivation Module
//! 
//! Argon2id password hashing

use super::{CryptoError, MasterKey};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};

/// Argon2 configuration
#[derive(Debug, Clone)]
pub struct Argon2Config {
    /// Memory cost in KiB (default: 64 MB)
    pub memory: u32,
    /// Number of iterations
    pub iterations: u32,
    /// Parallelism
    pub parallelism: u32,
    /// Output length in bytes
    pub output_len: usize,
}

impl Default for Argon2Config {
    fn default() -> Self {
        Self {
            memory: 65536,   // 64 MiB
            iterations: 3,
            parallelism: 4,
            output_len: 64, // 32 for vault key + 32 for MAC key
        }
    }
}

/// KDF configuration (for trait compatibility)
pub struct KdfConfig(pub Argon2Config);

impl Default for KdfConfig {
    fn default() -> Self {
        Self(Argon2Config::default())
    }
}

/// Derive a master key from a password using Argon2id
pub fn derive_key(password: &str, salt: &[u8], config: &Argon2Config) -> Result<MasterKey, CryptoError> {
    // Convert salt to SaltString
    let salt_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        salt
    );
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    
    // Configure Argon2
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            config.memory,
            config.iterations,
            config.parallelism,
            Some(config.output_len)
        ).map_err(|e| CryptoError::KeyDerivation(e.to_string()))?
    );
    
    // Hash password
    let hash = argon2.hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    
    // Extract hash output
    let hash_bytes = hash.hash.ok_or_else(|| 
        CryptoError::KeyDerivation("No hash output".to_string())
    )?;
    
    // Convert to bytes
    let mut derived = [0u8; 64];
    let hash_slice = hash_bytes.as_bytes();
    derived.copy_from_slice(&hash_slice[..64.min(hash_slice.len())]);
    
    Ok(MasterKey::from_derived(derived))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_derive_key() {
        let password = "test_password";
        let salt = [0u8; 32];
        let config = Argon2Config::default();
        
        let result = derive_key(password, &salt, &config);
        assert!(result.is_ok());
        
        let master_key = result.unwrap();
        assert_eq!(master_key.vault_key.as_bytes().len(), 32);
        assert_eq!(master_key.mac_key.as_bytes().len(), 32);
    }
}
