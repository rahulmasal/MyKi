//! Tauri commands for browser extension
//! Provides IPC (Inter-Process Communication) interface between the browser extension frontend and the native Rust backend.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use crate::crypto::generate_password as crypto_generate_password;
use crate::vault::{self, Credential, VaultStatus, VAULT};

/// Retrieves credentials that match a specific URL.
///
/// This command is called by the frontend to find credentials for the website currently
/// open in the browser. It requires the vault to be unlocked.
///
/// # Arguments
/// * `url` - The full URL of the website to match against.
///
/// # Returns
/// * `Ok(Vec<Credential>)` - A list of matching credentials, decrypted and ready for use.
/// * `Err(String)` - An error message if the vault is locked or matching fails.
#[tauri::command]
pub fn get_credentials_for_url(url: String) -> Result<Vec<Credential>, String> {
    // Lock the global vault state for thread-safe access
    let vault = VAULT.lock().map_err(|e| e.to_string())?;
    
    // Security check: Ensure the vault is unlocked before allowing access
    if !vault.is_unlocked {
        return Err("Vault is locked".to_string());
    }
    
    // Extract the active database connection and master key
    let conn = vault.connection.as_ref().ok_or("No connection")?;
    let master_key = vault.master_key.as_ref().ok_or("No master key")?;
    
    // Perform the lookup and decryption in the vault module
    vault::get_credentials_for_url(conn, master_key, &url)
}

/// Searches for credentials matching a query string.
///
/// Filters credentials by title, username, or URL pattern.
///
/// # Arguments
/// * `query` - The search term provided by the user in the frontend.
#[tauri::command]
pub fn search_credentials(query: String) -> Result<Vec<Credential>, String> {
    let vault = VAULT.lock().map_err(|e| e.to_string())?;
    
    if !vault.is_unlocked {
        return Err("Vault is locked".to_string());
    }
    
    let conn = vault.connection.as_ref().ok_or("No connection")?;
    let master_key = vault.master_key.as_ref().ok_or("No master key")?;
    
    vault::search_credentials(conn, master_key, &query)
}

/// Records that a credential was used to fill a form.
///
/// Increments the `use_count` in the database for the specified credential.
///
/// # Arguments
/// * `credential_id` - The unique UUID of the credential being used.
#[tauri::command]
pub fn fill_credential(credential_id: String) -> Result<(), String> {
    let vault = VAULT.lock().map_err(|e| e.to_string())?;
    
    if !vault.is_unlocked {
        return Err("Vault is locked".to_string());
    }
    
    let conn = vault.connection.as_ref().ok_or("No connection")?;
    
    vault::increment_use_count(conn, &credential_id)
}

/// Generates a secure, random password based on provided criteria.
///
/// This is a utility command that doesn't interact with the vault storage.
///
/// # Arguments
/// * `length` - Number of characters in the password.
/// * `include_uppercase` - Whether to include 'A-Z'.
/// * `include_lowercase` - Whether to include 'a-z'.
/// * `include_numbers` - Whether to include '0-9'.
/// * `include_symbols` - Whether to include special characters like '!@#$'.
#[tauri::command]
pub fn generate_password(
    length: usize,
    include_uppercase: bool,
    include_lowercase: bool,
    include_numbers: bool,
    include_symbols: bool,
) -> String {
    crypto_generate_password(
        length,
        include_uppercase,
        include_lowercase,
        include_numbers,
        include_symbols,
    )
}

/// Configuration options for password generation, used by the frontend.
#[derive(Debug, Deserialize, Serialize)]
pub struct PasswordOptions {
    /// Desired password length.
    pub length: usize,
    /// Enable uppercase letters.
    pub include_uppercase: bool,
    /// Enable lowercase letters.
    pub include_lowercase: bool,
    /// Enable numeric digits.
    pub include_numbers: bool,
    /// Enable special symbols.
    pub include_symbols: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            include_uppercase: true,
            include_lowercase: true,
            include_numbers: true,
            include_symbols: true,
        }
    }
}

/// Attempts to unlock the vault using a master password.
///
/// This command:
/// 1. Locates the vault database file.
/// 2. Derives a master key from the provided password.
/// 3. Verifies the password against the stored hash.
/// 4. If successful, stores the decrypted master key in memory for the duration of the session.
///
/// # Arguments
/// * `app_handle` - Tauri application handle to access local file paths.
/// * `password` - The master password entered by the user.
#[tauri::command]
pub fn unlock_vault(app_handle: AppHandle, password: String) -> Result<(), String> {
    // Resolve the application data directory where the database is stored
    let vault_dir = app_handle
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?;
    
    // Ensure the directory exists
    std::fs::create_dir_all(&vault_dir).map_err(|e| e.to_string())?;
    
    let db_path = vault_dir.join("vault.db");
    
    let mut vault = VAULT.lock().map_err(|e| e.to_string())?;
    
    // Check if vault exists
    if !vault_dir.join("vault.db").exists() {
        return Err("Vault does not exist".to_string());
    }
    
    // Validate password and derive the master key (Argon2id)
    let master_key = vault::unlock_vault(&db_path, &password)?;
    
    // Ensure database tables are initialized (migration safety)
    vault::init_vault(&db_path)?;
    
    // Open a persistent connection for the session
    let conn = rusqlite::Connection::open(&db_path).map_err(|e| e.to_string())?;
    
    // Update the global vault state
    vault.is_unlocked = true;
    vault.connection = Some(conn);
    vault.master_key = Some(master_key);
    
    tracing::info!("Vault unlocked successfully");
    
    Ok(())
}

/// Locks the vault and clears sensitive data from memory.
///
/// Discards the master key and closes the database connection.
#[tauri::command]
pub fn lock_vault() -> Result<(), String> {
    let mut vault = VAULT.lock().map_err(|e| e.to_string())?;
    
    // Clear state
    vault.is_unlocked = false;
    vault.connection = None;
    vault.master_key = None;
    
    tracing::info!("Vault locked");
    
    Ok(())
}

/// Checks if the vault is currently unlocked.
///
/// Used by the frontend to decide whether to show the login screen or the vault content.
#[tauri::command]
pub fn is_vault_unlocked() -> Result<bool, String> {
    let vault = VAULT.lock().map_err(|e| e.to_string())?;
    Ok(vault.is_unlocked)
}

/// Retrieves the overall status of the vault (existence, lock state, etc.).
#[tauri::command]
pub fn get_vault_status(app_handle: AppHandle) -> Result<VaultStatus, String> {
    let vault_dir = app_handle
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?;
    
    let db_path = vault_dir.join("vault.db");
    
    vault::get_vault_status(&db_path)
}

/// Adds a new credential to the vault.
///
/// Encrypts sensitive fields (password, notes, totp) before storing them in the database.
#[tauri::command]
pub fn add_credential(
    title: String,
    username: String,
    password: String,
    url_pattern: Option<String>,
    notes: Option<String>,
    totp_secret: Option<String>,
) -> Result<Credential, String> {
    let vault = VAULT.lock().map_err(|e| e.to_string())?;
    
    if !vault.is_unlocked {
        return Err("Vault is locked".to_string());
    }
    
    let conn = vault.connection.as_ref().ok_or("No connection")?;
    let master_key = vault.master_key.as_ref().ok_or("No master key")?;
    
    vault::add_credential(
        conn,
        master_key,
        &title,
        &username,
        &password,
        url_pattern.as_deref(),
        notes.as_deref(),
        totp_secret.as_deref(),
    )
}

/// Updates an existing credential.
///
/// Re-encrypts and overwrites the specified credential record.
#[tauri::command]
pub fn update_credential(
    id: String,
    title: String,
    username: String,
    password: String,
    url_pattern: Option<String>,
    notes: Option<String>,
) -> Result<(), String> {
    let vault = VAULT.lock().map_err(|e| e.to_string())?;
    
    if !vault.is_unlocked {
        return Err("Vault is locked".to_string());
    }
    
    let conn = vault.connection.as_ref().ok_or("No connection")?;
    let master_key = vault.master_key.as_ref().ok_or("No master key")?;
    
    vault::update_credential(
        conn,
        master_key,
        &id,
        &title,
        &username,
        &password,
        url_pattern.as_deref(),
        notes.as_deref(),
    )
}

/// Permanently removes a credential from the vault.
///
/// # Arguments
/// * `id` - The unique identifier of the credential to delete.
#[tauri::command]
pub fn delete_credential(id: String) -> Result<(), String> {
    let vault = VAULT.lock().map_err(|e| e.to_string())?;
    
    if !vault.is_unlocked {
        return Err("Vault is locked".to_string());
    }
    
    let conn = vault.connection.as_ref().ok_or("No connection")?;
    
    vault::delete_credential(conn, &id)
}
