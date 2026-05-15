//! TOTP Generator - RFC 6238 Compliant Implementation
//! 
//! This module implements the Time-based One-Time Password (TOTP) algorithm as specified
//! in RFC 6238. TOTP is used for two-factor authentication in many online services.
//! 
//! # Algorithm Overview
//! 
//! 1. **Get current time**: Unix timestamp in seconds
//! 2. **Compute counter**: floor(timestamp / period), typically 30 seconds
//! 3. **HMAC**: Compute HMAC-SHA1 of counter using shared secret
//! 4. **Dynamic Truncation**: Extract 6 digits from the HMAC result
//! 
//! # Supported Algorithms
//! 
//! - SHA1 (default, most common)
//! - SHA256 (more secure)
//! - SHA512 (highest security)

use hmac::{Hmac, Mac};  // HMAC implementation
use sha1::Sha1;         // SHA-1 hash (160-bit output)
use sha2::{Sha256, Sha512};  // SHA-2 family hashes
use thiserror::Error;   // Error handling derive macro

// Define HMAC type aliases for cleaner code
// Hmac<Sha1> is HMAC-SHA1, etc.
type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

// ---------------------------------------------------------------------------
// Algorithm Type
// ---------------------------------------------------------------------------

/// Supported hashing algorithms for TOTP generation.
/// 
/// Different services may require different algorithms:
/// - SHA1: Most common, used by Google, GitHub, etc.
/// - SHA256: More secure, used by some modern services
/// - SHA512: Highest security, used by enterprise systems
/// 
/// # Security Note
/// 
/// SHA1 is technically vulnerable to collision attacks, but HMAC-SHA1 is not
/// vulnerable because of the key input. SHA1 is still considered safe for TOTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]  // Default gives SHA1
pub enum Algorithm {
    /// The most common algorithm used for TOTP (RFC 6238 default).
    /// Used by Google Authenticator, GitHub, most services.
    #[default]
    SHA1,
    
    /// A more modern and secure hashing algorithm (256-bit output).
    /// Provides more bits of security than SHA1.
    SHA256,
    
    /// The strongest hashing algorithm supported (512-bit output).
    /// Provides maximum security but less compatibility.
    SHA512,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration settings for generating TOTP codes.
/// 
/// These settings control the format and timing of generated codes.
/// Most services use the defaults, but some may have custom requirements.
/// 
/// # Example
/// 
/// ```rust
/// use myki_core::totp::{Totp, TotpConfig, Algorithm};
/// 
/// // Default: SHA1, 6 digits, 30 second period
/// let config = TotpConfig::default();
/// 
/// // Custom configuration
/// let config = TotpConfig {
///     algorithm: Algorithm::SHA256,
///     digits: 8,    // 8-digit code
///     period: 30,   // 30 second window
/// };
/// ```
#[derive(Debug, Clone)]
pub struct TotpConfig {
    /// The hashing algorithm to use for HMAC.
    /// 
    /// Default: Algorithm::SHA1
    /// Most services use SHA1, but some modern services use SHA256 or SHA512.
    pub algorithm: Algorithm,
    
    /// The number of digits in the generated code.
    /// 
    /// Default: 6
    /// Common values: 6 or 8. 6 is standard (1 in a million chance per guess).
    pub digits: u8,
    
    /// How many seconds a code remains valid.
    /// 
    /// Default: 30
    /// Standard values: 30 or 60 seconds. 30 is most common.
    pub period: u64,
}

impl Default for TotpConfig {
    /// Provides the standard RFC 6238 settings: SHA1, 6 digits, 30-second period.
    /// 
    /// These defaults match Google Authenticator and most other TOTP implementations.
    fn default() -> Self {
        Self {
            algorithm: Algorithm::SHA1,  // Most compatible
            digits: 6,                  // Standard 6-digit codes
            period: 30,                  // 30-second windows
        }
    }
}

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors that can occur during TOTP generation or validation.
/// 
/// These errors indicate problems with the TOTP secret or the generation process.
#[derive(Error, Debug)]
pub enum TotpError {
    /// The provided secret key is not a valid Base32 string.
    /// 
    /// TOTP secrets must be encoded in Base32 (RFC 4648).
    /// Valid characters: A-Z, 2-7 (case-insensitive)
    #[error("Invalid secret: {0}")]
    InvalidSecret(String),
    
    /// An error occurred during the cryptographic hashing process.
    /// 
    /// This is typically an internal error and should not happen with valid inputs.
    #[error("Generation failed: {0}")]
    Generation(String),
}

// ---------------------------------------------------------------------------
// TOTP Generator
// ---------------------------------------------------------------------------

/// A stateless generator for Time-based One-Time Passwords (TOTP).
/// 
/// This struct provides static methods for generating and verifying TOTP codes.
/// No instance state is needed - all parameters are passed to each method call.
/// 
/// # Usage
/// 
/// ```rust
/// use myki_core::totp::{Totp, TotpConfig};
/// 
/// let secret = "GEZDGNBVGY3TQOJQ";  // Base32-encoded secret
/// let config = TotpConfig::default();
/// 
/// // Generate code for current time
/// let code = Totp::now(secret, &config).unwrap();
/// println!("Current code: {}", code);  // e.g., "123456"
/// 
/// // Get time remaining
/// let seconds = Totp::remaining_seconds(&config);
/// println!("Expires in: {} seconds", seconds);
/// ```
pub struct Totp;

impl Totp {
    /// Generates a TOTP code for a specific point in time.
    /// 
    /// This is the core TOTP algorithm. Given a secret and configuration,
    /// it computes the TOTP code for the given timestamp.
    /// 
    /// # Parameters
    /// 
    /// * `secret`: The Base32-encoded secret key shared between user and service.
    ///              This is typically provided as a string like "GEZDGNBVGY3TQOJQ"
    ///              or from scanning a QR code during 2FA setup.
    /// 
    /// * `config`: Configuration specifying algorithm, digits, and period.
    ///              Use `TotpConfig::default()` for standard settings.
    /// 
    /// * `timestamp`: The Unix timestamp (seconds since epoch) for which to generate.
    ///                 Use `SystemTime::now()` for current time.
    /// 
    /// # Returns
    /// 
    /// * `Ok(String)`: The TOTP code as a zero-padded string (e.g., "123456")
    /// * `Err(TotpError)`: If the secret is invalid or generation failed
    /// 
    /// # Algorithm Steps
    /// 
    /// 1. Decode the Base32 secret to raw bytes
    /// 2. Compute counter = timestamp / period (integer division)
    /// 3. Convert counter to 8-byte big-endian format
    /// 4. Compute HMAC using the configured algorithm
    /// 5. Apply dynamic truncation to extract digits
    pub fn generate(secret: &str, config: &TotpConfig, timestamp: i64) -> Result<String, TotpError> {
        // -----------------------------------------------------------------------
        // Step 1: Decode Base32 secret
        // -----------------------------------------------------------------------
        // The secret is stored/transmitted as Base32 for readability.
        // We need to decode it to raw bytes for HMAC computation.
        let secret_bytes = Self::decode_base32(secret)?;
        
        // -----------------------------------------------------------------------
        // Step 2: Compute time counter
        // -----------------------------------------------------------------------
        // TOTP divides time into fixed windows. Each window has the same code.
        // counter = floor(timestamp / period)
        // 
        // Example: With period=30, timestamp=1700000000
        // counter = 1700000000 / 30 = 56666666
        let counter = (timestamp / config.period as i64) as u64;
        
        // -----------------------------------------------------------------------
        // Step 3: Compute HMAC based on algorithm
        // -----------------------------------------------------------------------
        // HMAC (Hash-based Message Authentication Code) combines:
        // - The secret key
        // - The counter value
        // 
        // The algorithm (SHA1/SHA256/SHA512) determines the hash function used.
        let code = match config.algorithm {
            Algorithm::SHA1 => Self::hotp_sha1(&secret_bytes, counter, config.digits)?,
            Algorithm::SHA256 => Self::hotp_sha256(&secret_bytes, counter, config.digits)?,
            Algorithm::SHA512 => Self::hotp_sha512(&secret_bytes, counter, config.digits)?,
        };
        
        Ok(code)
    }
    
    /// Generates a TOTP code for the current system time.
    /// 
    /// This is a convenience method that gets the current timestamp automatically.
    /// 
    /// # Example
    /// 
    /// ```rust
    /// use myki_core::totp::{Totp, TotpConfig};
    /// 
    /// let code = Totp::now("SECRET", &TotpConfig::default()).unwrap();
    /// ```
    pub fn now(secret: &str, config: &TotpConfig) -> Result<String, TotpError> {
        // Get current system time as Unix timestamp
        // SystemTime::now() returns current time
        // duration_since(UNIX_EPOCH) gives seconds since 1970-01-01
        // unwrap() is safe because current time is always after epoch
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        Self::generate(secret, config, timestamp)
    }
    
    /// Calculates the number of seconds remaining until the current TOTP code expires.
    /// 
    /// This is useful for UI countdown timers that show when the code will change.
    /// 
    /// # Returns
    /// 
    /// Number of seconds remaining in the current period (1-30 for 30-second period).
    pub fn remaining_seconds(config: &TotpConfig) -> u64 {
        // Get current time as Unix timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // period - (now % period) = seconds until next period
        // Example: now=1700000015, period=30
        // remaining = 30 - (1700000015 % 30) = 30 - 15 = 15 seconds
        config.period - (now % config.period)
    }
    
    /// Verifies if a given TOTP code is valid for the current time.
    /// 
    /// This method checks not only the current time window but also adjacent
    /// windows to account for clock drift between the client and server.
    /// 
    /// # Parameters
    /// 
    /// * `secret`: The Base32-encoded TOTP secret
    /// * `config`: TOTP configuration
    /// * `code`: The code to verify
    /// * `tolerance`: Number of previous/future time periods to check (for clock drift)
    /// 
    /// # Returns
    /// 
    /// * `true` if the code is valid at the current time
    /// * `false` otherwise
    /// 
    /// # Example
    /// 
    /// ```rust
    /// use myki_core::totp::{Totp, TotpConfig};
    /// 
    /// let secret = "SECRET";
    /// let config = TotpConfig::default();
    /// 
    /// // Verify a code (typically from user input)
    /// if Totp::verify(secret, &config, "123456", 1) {
    ///     println!("Code is valid!");
    /// }
    /// ```
    pub fn verify(secret: &str, config: &TotpConfig, code: &str, tolerance: u64) -> bool {
        // Get current time
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Check current period, past periods, AND future periods (for clock skew).
        // Some devices have clocks slightly ahead, so we check both directions.
        for offset in -(tolerance as i64)..=(tolerance as i64) {
            let ts = now + (config.period as i64 * offset);
            match Self::generate(secret, config, ts) {
                Ok(generated) if generated == code => return true,
                _ => continue,
            }
        }

        false
    }
    
    /// Computes HMAC-SHA1 for a given counter and extracts a TOTP code.
    /// 
    /// This is an internal helper method.
    fn hotp_sha1(secret: &[u8], counter: u64, digits: u8) -> Result<String, TotpError> {
        // Convert counter to bytes and compute HMAC
        let counter_bytes = Self::counter_bytes(counter);
        let mut mac = HmacSha1::new_from_slice(secret)
            .map_err(|e| TotpError::Generation(e.to_string()))?;
        mac.update(&counter_bytes);
        let result = mac.finalize().into_bytes();
        
        // Extract digits using dynamic truncation
        Self::dynamic_truncate(&result, digits)
    }
    
    /// Computes HMAC-SHA256 for a given counter and extracts a TOTP code.
    fn hotp_sha256(secret: &[u8], counter: u64, digits: u8) -> Result<String, TotpError> {
        let counter_bytes = Self::counter_bytes(counter);
        let mut mac = HmacSha256::new_from_slice(secret)
            .map_err(|e| TotpError::Generation(e.to_string()))?;
        mac.update(&counter_bytes);
        let result = mac.finalize().into_bytes();
        Self::dynamic_truncate(&result, digits)
    }
    
    /// Computes HMAC-SHA512 for a given counter and extracts a TOTP code.
    fn hotp_sha512(secret: &[u8], counter: u64, digits: u8) -> Result<String, TotpError> {
        let counter_bytes = Self::counter_bytes(counter);
        let mut mac = HmacSha512::new_from_slice(secret)
            .map_err(|e| TotpError::Generation(e.to_string()))?;
        mac.update(&counter_bytes);
        let result = mac.finalize().into_bytes();
        Self::dynamic_truncate(&result, digits)
    }
    
    /// Converts a counter value to an 8-byte big-endian byte array.
    /// 
    /// RFC 6238 specifies that the counter should be an 8-byte (64-bit) unsigned integer
    /// represented in big-endian byte order.
    /// 
    /// # Example
    /// 
    /// counter = 56666666
    /// bytes = [0x00, 0x00, 0x00, 0x00, 0x03, 0x60, 0xD3, 0x2A]
    fn counter_bytes(counter: u64) -> Vec<u8> {
        // For each byte position (7 down to 0), extract that byte from counter
        // This creates a big-endian (network byte order) representation
        (0..8).rev().map(|i| ((counter >> (i * 8)) & 0xff) as u8).collect()
    }
    
    /// Performs dynamic truncation as specified in RFC 4226 (HOTP).
    /// 
    /// This algorithm extracts a certain number of digits from the HMAC output.
    /// The extraction point is determined by the last nibble (4 bits) of the hash.
    /// 
    /// # Parameters
    /// 
    /// * `hash`: The HMAC output bytes
    /// * `digits`: Number of digits to extract (typically 6)
    /// 
    /// # Returns
    /// 
    /// The truncated value as a zero-padded string.
    /// 
    /// # Algorithm
    /// 
    /// ```ignore
    /// offset = hash[19] & 0xf        // Last nibble of hash
    /// binary = (hash[offset] & 0x7f) << 24  // Extract 4 bytes
    ///         | (hash[offset+1] << 16)        // at the offset
    ///         | (hash[offset+2] << 8)
    ///         | (hash[offset+3])
    /// digits = binary % 10^6          // Take modulo
    /// ```
    fn dynamic_truncate(hash: &[u8], digits: u8) -> Result<String, TotpError> {
        // Validate hash length (HMAC-SHA1 produces 20 bytes minimum)
        if hash.len() < 19 {
            return Err(TotpError::Generation("Hash too short for truncation".to_string()));
        }
        
        // Get the offset from the last nibble (bits 0-3 of last byte)
        // hash[hash.len() - 1] is the last byte
        // & 0x0f masks to just the lower 4 bits
        let offset = (hash[hash.len() - 1] & 0x0f) as usize;
        
        // Extract 4 bytes starting at offset (big-endian)
        // & 0x7f clears the high bit to avoid signed/unsigned issues
        let binary = u32::from_be_bytes([
            hash[offset] & 0x7f,  // Clear sign bit
            hash[offset + 1],
            hash[offset + 2],
            hash[offset + 3],
        ]);
        
        // Compute modulo based on desired digits
        // 10^6 = 1000000, giving a 6-digit number
        let modulo = 10_u32.pow(digits as u32);
        let code = binary % modulo;
        
        // Format with leading zeros (e.g., "001234")
        // {:0>width$} means: pad with '0', align right, minimum width = digits
        Ok(format!("{:0>width$}", code, width = digits as usize))
    }
    
    /// Decodes a Base32-encoded string to raw bytes.
    /// 
    /// Base32 uses an alphabet of A-Z (26 letters) and 2-7 (6 digits), 
    /// total 32 characters. It's case-insensitive and padding ('=') is optional.
    /// 
    /// # Example
    /// 
    /// ```rust
    /// let decoded = Totp::decode_base32("GEZDGNBVGY3TQOJQ").unwrap();
    /// // Returns: [0x48, 0x65, 0x78, 0x21, ...] (8 bytes)
    /// ```
    fn decode_base32(input: &str) -> Result<Vec<u8>, TotpError> {
        // -----------------------------------------------------------------------
        // Normalize input
        // -----------------------------------------------------------------------
        // Base32 is case-insensitive, so uppercase
        // Remove whitespace (spaces sometimes added for readability)
        // Remove padding ('=') if present (optional in some variants)
        let cleaned: String = input
            .to_uppercase()
            .chars()
            .filter(|c| !c.is_whitespace())  // Remove spaces
            .filter(|c| *c != '=')           // Remove padding
            .collect();
        
        // -----------------------------------------------------------------------
        // Decode
        // -----------------------------------------------------------------------
        // Try without padding first, then with padding
        // The base32 crate handles the actual decoding
        base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned)
            .or_else(|| base32::decode(base32::Alphabet::Rfc4648 { padding: true }, input))
            .ok_or_else(|| TotpError::InvalidSecret("Invalid base32 encoding".to_string()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    
    /// Test that default configuration produces 6-digit codes.
    #[test]
    fn test_totp_default() {
        // A known test vector (Base32 encoded "Hello!" = 0x48656c6c6f21)
        let secret = "GEZDGNBVGY3TQOJQ";
        let config = TotpConfig::default();
        
        let code = Totp::now(secret, &config);
        assert!(code.is_ok());
        assert_eq!(code.unwrap().len(), 6);  // Should be 6 digits
    }
    
    /// Test that the same inputs produce the same code (deterministic).
    #[test]
    fn test_totp_deterministic() {
        let secret = "SECRET";
        let config = TotpConfig::default();
        
        // Generate at a fixed timestamp (1609459200 = 2021-01-01 00:00:00 UTC)
        let code1 = Totp::generate(secret, &config, 1609459200).unwrap();
        let code2 = Totp::generate(secret, &config, 1609459200).unwrap();
        
        assert_eq!(code1, code2);
    }
    
    /// Test verification with correct code.
    #[test]
    fn test_verify_correct_code() {
        let secret = "SECRET";
        let config = TotpConfig::default();
        
        // Generate current code
        let code = Totp::now(secret, &config).unwrap();
        
        // Should verify
        assert!(Totp::verify(secret, &config, &code, 1));
    }
    
    /// Test verification with incorrect code.
    #[test]
    fn test_verify_incorrect_code() {
        let secret = "SECRET";
        let config = TotpConfig::default();
        
        // Wrong code
        assert!(!Totp::verify(secret, &config, "000000", 1));
    }
}
