//! Key Derivation Module
//! 
//! Argon2id password hashing

use super::{CryptoError, MasterKey};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};

/// Configuration parameters for the Argon2id key derivation function.
/// 
/// Argon2id is a modern, secure password hashing algorithm that is resistant to 
/// side-channel attacks and GPU-based cracking.
#[derive(Debug, Clone)]
pub struct Argon2Config {
    /// The amount of memory used by the algorithm in KiB. 
    /// Higher values increase the cost of hardware attacks.
    pub memory: u32,
    /// The number of passes over the memory. 
    /// Higher values increase the time cost of the algorithm.
    pub iterations: u32,
    /// The number of threads to use. 
    /// This should generally be tuned to the target system's CPU cores.
    pub parallelism: u32,
    /// The length of the generated key in bytes.
    pub output_len: usize,
}

impl Default for Argon2Config {
    /// Provides recommended default settings for Argon2id.
    fn default() -> Self {
        Self {
            memory: 65536,   // 64 MiB
            iterations: 3,
            parallelism: 4,
            output_len: 64, // 32 for vault key + 32 for MAC key
        }
    }
}

/// A wrapper around `Argon2Config` for use with key derivation traits.
#[derive(Default)]
pub struct KdfConfig(pub Argon2Config);

#[allow(clippy::derivable_impls)]
impl KdfConfig {
    /// Creates a new `KdfConfig` with the given Argon2 settings.
    pub fn new(config: Argon2Config) -> Self {
        Self(config)
    }
}

/// Derives a `MasterKey` from a password and salt using the Argon2id algorithm.
/// 
/// # Parameters
/// - `password`: The user's master password.
/// - `salt`: A unique, random set of bytes used to make the hash unique even for common passwords.
/// - `config`: Argon2 parameters (memory, iterations, etc.).
/// 
/// # Returns
/// - `Ok(MasterKey)` containing the derived encryption and MAC keys.
/// - `Err(CryptoError)` if derivation fails.
pub fn derive_key(password: &str, salt: &[u8], config: &Argon2Config) -> Result<MasterKey, CryptoError> {
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
