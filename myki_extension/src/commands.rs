//! Tauri commands for browser extension
//! Provides IPC interface between browser extension and native app

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use crate::crypto::generate_password as crypto_generate_password;
use crate::vault::{self, Credential, VaultStatus, VAULT};

/// Get credentials for a URL
#[tauri::command]
pub fn get_credentials_for_url(url: String) -> Result<Vec<Credential>, String> {
    let vault = VAULT.lock().map_err(|e| e.to_string())?;
    
    if !vault.is_unlocked {
        return Err("Vault is locked".to_string());
    }
    
    let conn = vault.connection.as_ref().ok_or("No connection")?;
    let master_key = vault.master_key.as_ref().ok_or("No master key")?;
    
    vault::get_credentials_for_url(conn, master_key, &url)
}

/// Search credentials
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

/// Fill credential (increment use count)
#[tauri::command]
pub fn fill_credential(credential_id: String) -> Result<(), String> {
    let vault = VAULT.lock().map_err(|e| e.to_string())?;
    
    if !vault.is_unlocked {
        return Err("Vault is locked".to_string());
    }
    
    let conn = vault.connection.as_ref().ok_or("No connection")?;
    
    vault::increment_use_count(conn, &credential_id)
}

/// Generate password
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

/// Password options for generation
#[derive(Debug, Deserialize, Serialize)]
pub struct PasswordOptions {
    pub length: usize,
    pub include_uppercase: bool,
    pub include_lowercase: bool,
    pub include_numbers: bool,
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

/// Unlock vault with password
#[tauri::command]
pub fn unlock_vault(app_handle: AppHandle, password: String) -> Result<(), String> {
    let vault_dir = app_handle
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?;
    
    std::fs::create_dir_all(&vault_dir).map_err(|e| e.to_string())?;
    
    let db_path = vault_dir.join("vault.db");
    
    let mut vault = VAULT.lock().map_err(|e| e.to_string())?;
    
    // Check if vault exists
    if !vault_dir.join("vault.db").exists() {
        return Err("Vault does not exist".to_string());
    }
    
    // Unlock vault
    let master_key = vault::unlock_vault(&db_path, &password)?;
    
    // Initialize database
    vault::init_vault(&db_path)?;
    
    // Open connection
    let conn = rusqlite::Connection::open(&db_path).map_err(|e| e.to_string())?;
    
    vault.is_unlocked = true;
    vault.connection = Some(conn);
    vault.master_key = Some(master_key);
    
    tracing::info!("Vault unlocked successfully");
    
    Ok(())
}

/// Lock vault
#[tauri::command]
pub fn lock_vault() -> Result<(), String> {
    let mut vault = VAULT.lock().map_err(|e| e.to_string())?;
    
    vault.is_unlocked = false;
    vault.connection = None;
    vault.master_key = None;
    
    tracing::info!("Vault locked");
    
    Ok(())
}

/// Check if vault is unlocked
#[tauri::command]
pub fn is_vault_unlocked() -> Result<bool, String> {
    let vault = VAULT.lock().map_err(|e| e.to_string())?;
    Ok(vault.is_unlocked)
}

/// Get vault status
#[tauri::command]
pub fn get_vault_status(app_handle: AppHandle) -> Result<VaultStatus, String> {
    let vault_dir = app_handle
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?;
    
    let db_path = vault_dir.join("vault.db");
    
    vault::get_vault_status(&db_path)
}

/// Add new credential
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

/// Update credential
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

/// Delete credential
#[tauri::command]
pub fn delete_credential(id: String) -> Result<(), String> {
    let vault = VAULT.lock().map_err(|e| e.to_string())?;
    
    if !vault.is_unlocked {
        return Err("Vault is locked".to_string());
    }
    
    let conn = vault.connection.as_ref().ok_or("No connection")?;
    
    vault::delete_credential(conn, &id)
}
