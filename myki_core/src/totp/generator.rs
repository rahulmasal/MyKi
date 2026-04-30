//! TOTP Generator
//! 
//! RFC 6238 compliant TOTP implementation

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use thiserror::Error;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// Supported hashing algorithms for TOTP generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    /// The most common algorithm used for TOTP (RFC 6238).
    #[default]
    SHA1,
    /// A more modern and secure hashing algorithm.
    SHA256,
    /// The strongest hashing algorithm supported, providing the most bits of security.
    SHA512,
}

/// Configuration settings for generating TOTP codes.
#[derive(Debug, Clone)]
pub struct TotpConfig {
    /// The hashing algorithm to use (usually SHA1).
    pub algorithm: Algorithm,
    /// The number of digits in the generated code (usually 6).
    pub digits: u8,
    /// How many seconds a code remains valid (usually 30).
    pub period: u64,
}

impl Default for TotpConfig {
    /// Provides the standard RFC 6238 settings: SHA1, 6 digits, 30-second period.
    fn default() -> Self {
        Self {
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: 30,
        }
    }
}

/// Errors that can occur during TOTP generation or validation.
#[derive(Error, Debug)]
pub enum TotpError {
    /// The provided secret key is not a valid Base32 string.
    #[error("Invalid secret: {0}")]
    InvalidSecret(String),
    
    /// An error occurred during the cryptographic hashing process.
    #[error("Generation failed: {0}")]
    Generation(String),
}

/// A stateless generator for Time-based One-Time Passwords (TOTP).
pub struct Totp;

impl Totp {
    /// Generates a TOTP code for a specific point in time.
    /// 
    /// # Parameters
    /// - `secret`: The Base32-encoded secret key shared between the user and the service.
    /// - `config`: Configuration for the generation (algorithm, digits, period).
    /// - `timestamp`: The Unix timestamp for which to generate the code.
    pub fn generate(secret: &str, config: &TotpConfig, timestamp: i64) -> Result<String, TotpError> {
        // ... internal implementation ...
        let secret_bytes = Self::decode_base32(secret)?;
        
        let counter = (timestamp / config.period as i64) as u64;
        
        let code = match config.algorithm {
            Algorithm::SHA1 => Self::hotp_sha1(&secret_bytes, counter, config.digits)?,
            Algorithm::SHA256 => Self::hotp_sha256(&secret_bytes, counter, config.digits)?,
            Algorithm::SHA512 => Self::hotp_sha512(&secret_bytes, counter, config.digits)?,
        };
        
        Ok(code)
    }
    
    /// Generates a TOTP code for the current system time.
    pub fn now(secret: &str, config: &TotpConfig) -> Result<String, TotpError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        Self::generate(secret, config, timestamp)
    }
    
    /// Calculates the number of seconds remaining until the current TOTP code expires.
    pub fn remaining_seconds(config: &TotpConfig) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        config.period - (now % config.period)
    }
    
    /// Verifies if a given TOTP code is valid for the current time.
    /// 
    /// # Parameters
    /// - `tolerance`: The number of previous/future time periods to check to account for clock drift.
    pub fn verify(secret: &str, config: &TotpConfig, code: &str, tolerance: u64) -> bool {
        // ...
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        // Check current and previous periods
        for offset in 0..=tolerance {
            let ts = now - (config.period as i64 * offset as i64);
            match Self::generate(secret, config, ts) {
                Ok(generated) if generated == code => return true,
                _ => continue,
            }
        }
        
        false
    }
    
    fn hotp_sha1(secret: &[u8], counter: u64, digits: u8) -> Result<String, TotpError> {
        let counter_bytes = Self::counter_bytes(counter);
        let mut mac = HmacSha1::new_from_slice(secret)
            .map_err(|e| TotpError::Generation(e.to_string()))?;
        mac.update(&counter_bytes);
        let result = mac.finalize().into_bytes();
        Self::dynamic_truncate(&result, digits)
    }
    
    fn hotp_sha256(secret: &[u8], counter: u64, digits: u8) -> Result<String, TotpError> {
        let counter_bytes = Self::counter_bytes(counter);
        let mut mac = HmacSha256::new_from_slice(secret)
            .map_err(|e| TotpError::Generation(e.to_string()))?;
        mac.update(&counter_bytes);
        let result = mac.finalize().into_bytes();
        Self::dynamic_truncate(&result, digits)
    }
    
    fn hotp_sha512(secret: &[u8], counter: u64, digits: u8) -> Result<String, TotpError> {
        let counter_bytes = Self::counter_bytes(counter);
        let mut mac = HmacSha512::new_from_slice(secret)
            .map_err(|e| TotpError::Generation(e.to_string()))?;
        mac.update(&counter_bytes);
        let result = mac.finalize().into_bytes();
        Self::dynamic_truncate(&result, digits)
    }
    
    fn counter_bytes(counter: u64) -> Vec<u8> {
        (0..8).rev().map(|i| ((counter >> (i * 8)) & 0xff) as u8).collect()
    }
    
    fn dynamic_truncate(hash: &[u8], digits: u8) -> Result<String, TotpError> {
        let offset = (hash[hash.len() - 1] & 0x0f) as usize;
        let binary = u32::from_be_bytes([
            hash[offset] & 0x7f,
            hash[offset + 1],
            hash[offset + 2],
            hash[offset + 3],
        ]);
        
        let modulo = 10_u32.pow(digits as u32);
        let code = binary % modulo;
        
        Ok(format!("{:0>width$}", code, width = digits as usize))
    }
    
    fn decode_base32(input: &str) -> Result<Vec<u8>, TotpError> {
        let cleaned: String = input
            .to_uppercase()
            .chars()
            .filter(|c| !c.is_whitespace())
            .filter(|c| *c != '=')
            .collect();
        
        // Use base32 crate with RFC4648 alphabet
        base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned)
            .or_else(|| base32::decode(base32::Alphabet::Rfc4648 { padding: true }, input))
            .ok_or_else(|| TotpError::InvalidSecret("Invalid base32 encoding".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_totp_default() {
        let secret = "GEZDGNBVGY3TQOJQ";
        let config = TotpConfig::default();
        
        let code = Totp::now(secret, &config);
        assert!(code.is_ok());
        assert_eq!(code.unwrap().len(), 6);
    }
    
    #[test]
    fn test_totp_verify() {
        let secret = "GEZDGNBVGY3TQOJQ";
        let config = TotpConfig::default();
        
        let code = Totp::now(secret, &config).unwrap();
        assert!(Totp::verify(secret, &config, &code, 1));
        assert!(!Totp::verify(secret, &config, "000000", 1));
    }

    #[test]
    fn test_totp_different_times() {
        let secret = "JBSWY3DPEHPK3PXP";
        let config = TotpConfig::default();
        
        let code1 = Totp::generate(secret, &config, 1000).unwrap();
        let code2 = Totp::generate(secret, &config, 1000 + 30).unwrap();
        let code3 = Totp::generate(secret, &config, 1000 + 1).unwrap();
        
        assert_ne!(code1, code2);
        assert_eq!(code1, code3); // Same period
    }

    #[test]
    fn test_totp_invalid_base32() {
        let secret = "invalid base32!";
        let config = TotpConfig::default();
        let result = Totp::now(secret, &config);
        assert!(result.is_err());
    }
}
