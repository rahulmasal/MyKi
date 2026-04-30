//! Vault Module
//! 
//! Encrypted credential storage

pub mod database;
pub mod models;

pub use database::VaultDatabase;
pub use models::{Credential, CredentialNew, Identity, SecureNote, Folder, TotpSecret};
use thiserror::Error;

/// Errors that can occur during vault operations.
#[derive(Error, Debug)]
pub enum VaultError {
    /// An error occurred in the underlying SQLite database.
    #[error("Database error: {0}")]
    Database(String),
    
    /// Failed to encrypt data before saving it to the database.
    #[error("Encryption error: {0}")]
    Encryption(String),
    
    /// Failed to decrypt data retrieved from the database.
    #[error("Decryption error: {0}")]
    Decryption(String),
    
    /// The requested item (e.g., a specific credential ID) was not found.
    #[error("Not found: {0}")]
    NotFound(String),
    
    /// The requested operation is not allowed or invalid in the current state.
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
}
