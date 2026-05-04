//! Key Derivation Module
//! 
//! This module implements the Argon2id password hashing algorithm for secure key derivation.
//! 
//! # What is Key Derivation?
//! 
//! Key derivation transforms a user's password into a cryptographic key that can actually
//! be used for encryption. This is necessary because:
//! 
//! 1. Passwords are typically weak (short, memorable)
//! 2. Encryption requires keys of a specific length and format
//! 3. We don't want to store the actual password anywhere
//! 
//! # Why Argon2id?
//! 
//! Argon2id was the winner of the Password Hashing Competition in 2015. It's designed to:
//! 
//! - **Resist GPU attacks**: Uses memory that can't be efficiently parallelized on GPUs
//! - **Resist side-channel attacks**: Not vulnerable to cache timing attacks
//! - **Be tunable**: Parameters can be adjusted as hardware improves
//! 
//! # How It Works
//! 
//! ```
//! Password + Salt ──► Argon2id ──► 64 bytes of derived material
//!                                    ├── 32 bytes: VaultKey (encryption)
//!                                    └── 32 bytes: MacKey (authentication)
//! ```

use super::{CryptoError, MasterKey};  // Import error type and MasterKey from parent module
use argon2::{
    password_hash::{PasswordHasher, SaltString},  // High-level Argon2 API
    Argon2,  // The Argon2 algorithm implementation
};

// ---------------------------------------------------------------------------
// Configuration Types
// ---------------------------------------------------------------------------

/// Configuration parameters for the Argon2id key derivation function.
/// 
/// Argon2id is a modern, secure password hashing algorithm that combines
/// the properties of Argon2d (resistant to GPU) and Argon2i (resistant to
/// side-channel attacks) by using both data-dependent and data-independent memory access.
/// 
/// # Choosing Parameters
/// 
/// The parameters should be chosen to make brute-force attacks as expensive as possible
/// while still allowing legitimate users to derive keys in a reasonable time.
/// 
/// Default values (64 MiB, 3 iterations, 4 parallelism) take ~1-2 seconds on modern hardware.
#[derive(Debug, Clone)]  // Debug allows printing config for debugging; Clone for copying
pub struct Argon2Config {
    /// The amount of memory used by the algorithm in KiB (kibibytes).
    /// 
    /// Higher values increase the cost of hardware attacks because GPUs/APUs have
    /// limited memory bandwidth. 64 MiB (65536 KiB) is a good default.
    /// 
    /// # Security Note
    /// Memory hardness is the primary defense against parallel attacks.
    pub memory: u32,
    
    /// The number of passes over the memory.
    ///
    /// Higher values increase the computational cost. Each iteration processes
    /// the entire memory block again. 3 is a good balance.
    pub iterations: u32,
    
    /// The number of parallel threads to use.
    ///
    /// This should generally match the number of CPU cores available.
    /// Using more threads can speed up computation on multi-core systems.
    pub parallelism: u32,
    
    /// The length of the generated key in bytes.
    ///
    /// We generate 64 bytes total: 32 for VaultKey, 32 for MacKey.
    pub output_len: usize,
}

impl Default for Argon2Config {
    /// Provides recommended default settings for Argon2id.
    /// 
    /// These values are designed to be:
    /// - Secure: 64 MiB memory is substantial
    /// - Reasonably fast: ~1-2 seconds on modern hardware
    /// - Portable: Works well across different hardware configurations
    fn default() -> Self {
        Self {
            memory: 65536,   // 64 MiB in KiB
            iterations: 3,   // 3 passes over memory
            parallelism: 4,  // 4 threads (good for most modern CPUs)
            output_len: 64, // 64 bytes = 32 for vault key + 32 for MAC key
        }
    }
}

/// A wrapper around `Argon2Config` for use with key derivation traits.
/// 
/// This exists to provide a uniform interface for different KDF algorithms
/// (future-proofing for Argon2id -> Argon2 -> other KDFs).
/// 
/// Currently, this is a simple wrapper, but it allows for easier extension
/// if multiple KDF configurations are needed.
#[derive(Default)]  // Default gives sensible defaults via Argon2Config::default()
pub struct KdfConfig(pub Argon2Config);

#[allow(clippy::derivable_impls)]  // Suppress warning about deriving Default with manual impl
impl KdfConfig {
    /// Creates a new `KdfConfig` with the given Argon2 settings.
    /// 
    /// # Parameters
    /// 
    /// * `config`: The Argon2 configuration to use
    pub fn new(config: Argon2Config) -> Self {
        Self(config)
    }
}

// ---------------------------------------------------------------------------
// Key Derivation Function
// ---------------------------------------------------------------------------

/// Derives a `MasterKey` from a password and salt using the Argon2id algorithm.
/// 
/// This function takes a user's master password and a random salt, then runs
/// Argon2id to produce a cryptographically strong key. The derived key is then
/// split into two 32-byte keys: one for encryption and one for authentication.
/// 
/// # Parameters
/// 
/// * `password`: The user's master password. This should be a strong password
///               that the user has memorized. It's never stored directly.
/// 
/// * `salt`: A unique, random set of bytes used to make the derived key unique
///           even if two users have the same password. The salt should be:
///           - At least 16 bytes (our implementation uses 32)
///           - Generated using a cryptographically secure RNG
///           - Unique per user/vault
/// 
/// * `config`: Argon2 parameters (memory, iterations, parallelism, output length).
///             Use `Argon2Config::default()` for standard settings.
/// 
/// # Returns
/// 
/// * `Ok(MasterKey)` containing the derived encryption and MAC keys
/// * `Err(CryptoError)` if derivation fails
/// 
/// # Example
/// 
/// ```rust
/// use myki_core::crypto::{derive_key, Argon2Config};
/// 
/// let password = "my_secure_password";
/// let salt = [0u8; 32];  // In practice, use random salt
/// let config = Argon2Config::default();
/// 
/// let master_key = derive_key(password, &salt, &config).unwrap();
/// println!("Vault key: {:?}", master_key.vault_key.as_bytes());
/// ```
/// 
/// # Security Notes
/// 
/// 1. **Salt reuse**: Never use the same salt for multiple derivations
/// 2. **Password strength**: The security of your vault depends on password strength
/// 3. **Timing attacks**: This function uses constant-time operations internally
pub fn derive_key(password: &str, salt: &[u8], config: &Argon2Config) -> Result<MasterKey, CryptoError> {
    // -----------------------------------------------------------------------
    // Step 1: Encode the salt as base64 for Argon2's SaltString
    // -----------------------------------------------------------------------
    // SaltString::encode_b64 converts raw bytes to a base64 string format
    // that Argon2 expects. This is part of Argon2's input format.
    let salt_string = SaltString::encode_b64(salt)
        .map_err(|e| CryptoError::KeyDerivation(format!("Salt encoding failed: {}", e)))?;
    
    // -----------------------------------------------------------------------
    // Step 2: Configure the Argon2 algorithm
    // -----------------------------------------------------------------------
    // Argon2::new creates an Argon2id hasher with:
    // - Algorithm: Argon2id (the id variant combines memory hardness + side-channel resistance)
    // - Version: V0x13 (the latest version of Argon2)
    // - Params: memory, iterations, parallelism, output length
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,    // The id variant - best for password hashing
        argon2::Version::V0x13,         // Version 1.3 (latest)
        argon2::Params::new(
            config.memory,        // Memory in KiB
            config.iterations,    // Number of passes
            config.parallelism,   // Thread count
            Some(config.output_len)  // Output length in bytes
        ).map_err(|e| CryptoError::KeyDerivation(format!("Invalid parameters: {}", e)))?
    );
    
    // -----------------------------------------------------------------------
    // Step 3: Hash the password with the salt
    // -----------------------------------------------------------------------
    // hash_password performs the actual Argon2id computation:
    // - Takes the password bytes and salt
    // - Runs the memory-hard hashing algorithm
    // - Returns a PasswordHash that contains the result
    let hash = argon2.hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| CryptoError::KeyDerivation(format!("Hashing failed: {}", e)))?;
    
    // -----------------------------------------------------------------------
    // Step 4: Extract the derived key bytes
    // -----------------------------------------------------------------------
    // hash.hash contains the raw derived bytes. We need to extract them
    // and convert to our MasterKey structure.
    let hash_bytes = hash.hash.ok_or_else(|| 
        CryptoError::KeyDerivation("No hash output produced".to_string())
    )?;
    
    // -----------------------------------------------------------------------
    // Step 5: Convert to MasterKey
    // -----------------------------------------------------------------------
    // The hash output is 64 bytes. MasterKey::from_derived splits this into:
    // - First 32 bytes -> VaultKey (for AES-256-GCM encryption)
    // - Last 32 bytes -> MacKey (for message authentication)
    let mut derived = [0u8; 64];
    let hash_slice = hash_bytes.as_bytes();
    derived.copy_from_slice(&hash_slice[..64.min(hash_slice.len())]);
    
    Ok(MasterKey::from_derived(derived))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]  // Only compile tests when running cargo test
mod tests {
    use super::*;
    
    /// Tests that key derivation succeeds with default parameters.
    #[test]
    fn test_derive_key() {
        let password = "test_password";
        let salt = [0u8; 32];  // Zero salt for testing (not for production!)
        let config = Argon2Config::default();
        
        // Should succeed without error
        let result = derive_key(password, &salt, &config);
        assert!(result.is_ok());
        
        let master_key = result.unwrap();
        
        // Verify key lengths are correct
        assert_eq!(master_key.vault_key.as_bytes().len(), 32);
        assert_eq!(master_key.mac_key.as_bytes().len(), 32);
    }

    /// Tests that the same password + salt produces the same key.
    /// This is critical for reproducibility - the same credentials must unlock the same vault.
    #[test]
    fn test_derive_key_consistency() {
        let password = "test-password";
        let salt = [0u8; 16];  // 16 bytes of zeros
        let config = Argon2Config::default();
        
        // Derive key twice with same inputs
        let key1 = derive_key(password, &salt, &config).unwrap();
        let key2 = derive_key(password, &salt, &config).unwrap();
        
        // Keys should be identical
        assert_eq!(key1.vault_key.as_bytes(), key2.vault_key.as_bytes());
        assert_eq!(key1.mac_key.as_bytes(), key2.mac_key.as_bytes());
    }

    /// Tests that different passwords produce different keys.
    /// This is critical for security - one password shouldn't work for another.
    #[test]
    fn test_derive_key_different_password() {
        let salt = [0u8; 16];
        let config = Argon2Config::default();
        
        let key1 = derive_key("pwd1", &salt, &config).unwrap();
        let key2 = derive_key("pwd2", &salt, &config).unwrap();
        
        // Keys should be different
        assert_ne!(key1.vault_key.as_bytes(), key2.vault_key.as_bytes());
    }
}
