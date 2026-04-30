//! Time-based One-Time Password implementation (RFC 6238)
//! 
//! This module provides functionality for generating and verifying TOTP codes,
//! which are commonly used for Two-Factor Authentication (2FA).

pub mod generator;

pub use generator::Totp;
pub use crate::totp::generator::Algorithm;
pub use crate::totp::generator::TotpConfig;
pub use crate::totp::generator::TotpError;
