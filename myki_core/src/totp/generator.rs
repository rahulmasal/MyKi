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

/// TOTP algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    SHA1,
    SHA256,
    SHA512,
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::SHA1
    }
}

/// TOTP configuration
#[derive(Debug, Clone)]
pub struct TotpConfig {
    pub algorithm: Algorithm,
    pub digits: u8,
    pub period: u64,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: 30,
        }
    }
}

/// TOTP errors
#[derive(Error, Debug)]
pub enum TotpError {
    #[error("Invalid secret: {0}")]
    InvalidSecret(String),
    
    #[error("Generation failed: {0}")]
    Generation(String),
}

/// TOTP generator
pub struct Totp;

impl Totp {
    /// Generate a TOTP code
    pub fn generate(secret: &str, config: &TotpConfig, timestamp: i64) -> Result<String, TotpError> {
        // Decode base32 secret
        let secret_bytes = Self::decode_base32(secret)?;
        
        // Calculate time counter
        let counter = (timestamp / config.period as i64) as u64;
        
        // Generate HOTP with counter
        let code = match config.algorithm {
            Algorithm::SHA1 => Self::hotp_sha1(&secret_bytes, counter, config.digits)?,
            Algorithm::SHA256 => Self::hotp_sha256(&secret_bytes, counter, config.digits)?,
            Algorithm::SHA512 => Self::hotp_sha512(&secret_bytes, counter, config.digits)?,
        };
        
        Ok(code)
    }
    
    /// Generate TOTP for current time
    pub fn now(secret: &str, config: &TotpConfig) -> Result<String, TotpError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        Self::generate(secret, config, timestamp)
    }
    
    /// Get remaining seconds until code expires
    pub fn remaining_seconds(config: &TotpConfig) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        config.period - (now % config.period)
    }
    
    /// Verify a TOTP code (with tolerance for clock drift)
    pub fn verify(secret: &str, config: &TotpConfig, code: &str, tolerance: u64) -> bool {
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
}
