//! Time-based One-Time Password implementation (RFC 6238)
//! 
//! This module provides functionality for generating and verifying TOTP codes,
//! which are commonly used for Two-Factor Authentication (2FA).
//! 
//! # What is TOTP?
//! 
//! TOTP (Time-based One-Time Password) is a widely used authentication method where
//! a temporary code is generated from a shared secret and the current time. The code
//! is typically 6 digits and changes every 30 seconds.
//! 
//! # How It Works
//! 
//! ```
//! Shared Secret (Base32) ──► HMAC-SHA1 ──► Dynamic Truncation ──► 6-digit code
//!                                 ▲
//!                                 │
//!                     Current Unix Timestamp / 30
//! ```
//! 
//! # RFC 6238
//! 
//! This implementation follows RFC 6238, which standardizes TOTP. Most 2FA systems
//! (Google Authenticator, Microsoft Authenticator, Authy, etc.) use this standard.
//! 
//! # Security Properties
//! 
//! - **Time-based**: Codes expire after a short window (~30 seconds)
//! - **Shared Secret**: Both server and authenticator know the secret
//! - **One-time**: Each code can only be used once
//! - **No Network**: Works offline without internet connectivity

pub mod generator;  // TOTP generation implementation

// Re-export public types for easier access
pub use generator::Totp;  // Main TOTP generator struct
pub use crate::totp::generator::Algorithm;  // Hashing algorithm enum
pub use crate::totp::generator::TotpConfig;  // TOTP configuration
pub use crate::totp::generator::TotpError;  // TOTP errors
