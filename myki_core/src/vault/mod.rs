//! Vault Module
//! 
//! This module provides encrypted storage for credentials and other sensitive data
//! using SQLite as the underlying database engine.
//! 
//! # Security Model
//! 
//! All sensitive data is encrypted using AES-256-GCM before being stored in the database.
//! Only metadata (like the salt) is stored in plaintext.
//! 
//! # Data Flow
//! 
//! ```
//! User Data (Credential)
//!        │
//!        ▼
//! JSON Serialization (serde_json)
//!        │
//!        ▼
//! AES-256-GCM Encryption (vault_key)
//!        │
//!        ▼
//! Base64 Encoding
//!        │
//!        ▼
//! SQLite Database (storage)
//! ```
//! 
//! # Database Schema
//! 
//! - `vault_meta`: Key-value store for configuration
//! - `credentials`: Encrypted credential entries
//! - `identities`: Encrypted identity entries
//! - `secure_notes`: Encrypted text notes
//! - `folders`: Encrypted folder organization
//! - `totp_secrets`: TOTP configurations linked to credentials

pub mod database;  // SQLite database implementation
pub mod models;    // Data structures

// Re-export public types for easier access
pub use database::VaultDatabase;  // Main database handle
pub use models::{
    Credential,    // Username/password entry
    CredentialNew,  // For creating new credentials
    Identity,      // Personal information
    SecureNote,    // Encrypted text note
    Folder,        // Organization container
    TotpSecret,    // TOTP configuration
};
use thiserror::Error;  // Error handling derive macro

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors that can occur during vault operations.
/// 
/// These errors cover database errors, encryption/decryption failures,
/// and item-not-found scenarios.
#[derive(Error, Debug)]
pub enum VaultError {
    /// An error occurred in the underlying SQLite database.
    /// 
    /// This could be:
    /// - File not found or not accessible
    /// - Corrupted database
    /// - Query syntax error (shouldn't happen with our code)
    #[error("Database error: {0}")]
    Database(String),
    
    /// Failed to encrypt data before saving it to the database.
    /// 
    /// This is typically an internal error or indicates a problem with the key.
    #[error("Encryption error: {0}")]
    Encryption(String),
    
    /// Failed to decrypt data retrieved from the database.
    /// 
    /// This could indicate:
    /// - Wrong key used to open the vault
    /// - Corrupted ciphertext
    /// - Data was tampered with
    #[error("Decryption error: {0}")]
    Decryption(String),
    
    /// The requested item (e.g., a specific credential ID) was not found.
    /// 
    /// This happens when trying to access a credential that doesn't exist.
    #[error("Not found: {0}")]
    NotFound(String),
    
    /// The requested operation is not allowed or invalid in the current state.
    /// 
    /// For example, trying to save without a key set.
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
}
