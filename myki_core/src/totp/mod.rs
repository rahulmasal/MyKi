//! TOTP Module
//! 
//! Time-based One-Time Password implementation (RFC 6238)

pub mod generator;

pub use generator::Totp;
pub use crate::totp::generator::Algorithm;
pub use crate::totp::generator::TotpConfig;
pub use crate::totp::generator::TotpError;
