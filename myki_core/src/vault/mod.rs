//! Vault Module
//! 
//! Encrypted credential storage

pub mod database;
pub mod models;

pub use database::VaultDatabase;
pub use models::{Credential, CredentialNew, Identity, SecureNote, Folder, TotpSecret};
use thiserror::Error;

/// Vault operation errors
#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Database error: {0}")]
    Database(String),
    
    #[error("Encryption error: {0}")]
    Encryption(String),
    
    #[error("Decryption error: {0}")]
    Decryption(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
}
