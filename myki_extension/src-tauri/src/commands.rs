//! Tauri commands for Myki Desktop
//! Exposes vault functionality to the frontend

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::State;

use crate::crypto::{generate_password, MasterKey};
use crate::vault::{self, Credential, Vault, VAULT};

/// Database path state
pub struct AppState {
    pub db_path: Mutex<PathBuf>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            db_path: Mutex::new(PathBuf::new()),
        }
    }
}

/// Credential DTO for frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDto {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url_pattern: Option<String>,
    pub notes: Option<String>,
    pub totp_secret: Option<String>,
    pub favorite: bool,
}

/// Vault status DTO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultStatusDto {
    pub exists: bool,
    pub is_unlocked: bool,
    pub credential_count: i32,
}

/// Password generator options
#[derive(Debug, Deserialize)]
pub struct PasswordOptions {
    pub length: usize,
    pub include_uppercase: bool,
    pub include_lowercase: bool,
    pub include_numbers: bool,
    pub include_symbols: bool,
}

/// Create a new vault
#[tauri::command]
pub async fn create_vault(
    state: State<'_, AppState>,
    password: String,
    auto_lock_minutes: i32,
) -> Result<(), String> {
    let db_path = state.db_path.lock().unwrap().clone();
    vault::create_vault(&db_path, &password, auto_lock_minutes)
}

/// Setup desktop app (initialize paths)
#[tauri::command]
pub async fn setup_desktop(state: State<'_, AppState>) -> Result<(), String> {
    let mut db_path = state.db_path.lock().unwrap();
    if db_path.to_str().map(|s| s.is_empty()).unwrap_or(true) {
        // Use default path in app data directory
        let app_data = dirs::data_local_dir()
            .ok_or("Failed to get app data directory")?
            .join("Myki");
        std::fs::create_dir_all(&app_data)?;
        *db_path = app_data.join("vault.db");
        
        // Initialize vault
        vault::init_vault(&db_path)?;
    }
    Ok(())
}

/// Unlock the vault
#[tauri::command]
pub async fn unlock_vault(
    state: State<'_, AppState>,
    password: String,
) -> Result<(), String> {
    let db_path = state.db_path.lock().unwrap().clone();
    let master_key = vault::unlock_vault(&db_path, &password)?;
    
    let mut vault = VAULT.lock().unwrap();
    vault.is_unlocked = true;
    vault.master_key = Some(master_key);
    vault.connection = Some(Connection::open(&db_path).map_err(|e| e.to_string())?);
    
    Ok(())
}

/// Lock the vault
#[tauri::command]
pub async fn lock_vault() -> Result<(), String> {
    vault::lock_vault();
    Ok(())
}

/// Check if vault is unlocked
#[tauri::command]
pub async fn is_vault_unlocked() -> Result<bool, String> {
    let vault = VAULT.lock().unwrap();
    Ok(vault.is_unlocked)
}

/// Get vault status
#[tauri::command]
pub async fn get_vault_status(state: State<'_, AppState>) -> Result<VaultStatusDto, String> {
    let db_path = state.db_path.lock().unwrap().clone();
    let status = vault::get_vault_status(&db_path)?;
    
    Ok(VaultStatusDto {
        exists: status.exists,
        is_unlocked: status.is_unlocked,
        credential_count: status.credential_count,
    })
}

/// Get credentials for URL (for auto-fill)
#[tauri::command]
pub async fn get_credentials_for_url(
    state: State<'_, AppState>,
    url: String,
) -> Result<Vec<CredentialDto>, String> {
    let vault = VAULT.lock().unwrap();
    
    if !vault.is_unlocked {
        return Err("Vault is locked".to_string());
    }
    
    let connection = vault.connection.as_ref().ok_or("No connection")?;
    let master_key = vault.master_key.as_ref().ok_or("No master key")?;
    
    let credentials = vault::get_credentials_for_url(connection, master_key, &url)?;
    
    Ok(credentials.into_iter().map(|c| c.into()).collect())
}

/// Search credentials
#[tauri::command]
pub async fn search_credentials(
    state: State<'_, AppState>,
    query: String,
) -> Result<Vec<CredentialDto>, String> {
    let vault = VAULT.lock().unwrap();
    
    if !vault.is_unlocked {
        return Err("Vault is locked".to_string());
    }
    
    let connection = vault.connection.as_ref().ok_or("No connection")?;
    let master_key = vault.master_key.as_ref().ok_or("No master key")?;
    
    let credentials = vault::search_credentials(connection, master_key, &query)?;
    
    Ok(credentials.into_iter().map(|c| c.into()).collect())
}

/// Get all credentials
#[tauri::command]
pub async fn get_all_credentials(
    state: State<'_, AppState>,
) -> Result<Vec<CredentialDto>, String> {
    let vault = VAULT.lock().unwrap();
    
    if !vault.is_unlocked {
        return Err("Vault is locked".to_string());
    }
    
    let connection = vault.connection.as_ref().ok_or("No connection")?;
    let master_key = vault.master_key.as_ref().ok_or("No master key")?;
    
    let credentials = vault::get_all_credentials(connection, master_key)?;
    
    Ok(credentials.into_iter().map(|c| c.into()).collect())
}

/// Add a new credential
#[tauri::command]
pub async fn add_credential(
    state: State<'_, AppState>,
    title: String,
    username: String,
    password: String,
    url_pattern: Option<String>,
    notes: Option<String>,
    totp_secret: Option<String>,
) -> Result<CredentialDto, String> {
    let vault = VAULT.lock().unwrap();
    
    if !vault.is_unlocked {
        return Err("Vault is locked".to_string());
    }
    
    let connection = vault.connection.as_ref().ok_or("No connection")?;
    let master_key = vault.master_key.as_ref().ok_or("No master key")?;
    
    let credential = vault::add_credential(
        connection,
        master_key,
        &title,
        &username,
        &password,
        url_pattern.as_deref(),
        notes.as_deref(),
        totp_secret.as_deref(),
    )?;
    
    Ok(credential.into())
}

/// Update credential
#[tauri::command]
pub async fn update_credential(
    state: State<'_, AppState>,
    id: String,
    title: String,
    username: String,
    password: String,
    url_pattern: Option<String>,
    notes: Option<String>,
) -> Result<(), String> {
    let vault = VAULT.lock().unwrap();
    
    if !vault.is_unlocked {
        return Err("Vault is locked".to_string());
    }
    
    let connection = vault.connection.as_ref().ok_or("No connection")?;
    let master_key = vault.master_key.as_ref().ok_or("No master key")?;
    
    vault::update_credential(
        connection,
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
pub async fn delete_credential(
    state: State<'_, AppState>,
    id: String,
) -> Result<(), String> {
    let vault = VAULT.lock().unwrap();
    
    if !vault.is_unlocked {
        return Err("Vault is locked".to_string());
    }
    
    let connection = vault.connection.as_ref().ok_or("No connection")?;
    
    vault::delete_credential(connection, &id)
}

/// Generate password
#[tauri::command]
pub fn generate_password_cmd(options: PasswordOptions) -> String {
    generate_password(
        options.length,
        options.include_uppercase,
        options.include_lowercase,
        options.include_numbers,
        options.include_symbols,
    )
}

/// Fill credential (update use count)
#[tauri::command]
pub async fn fill_credential(
    state: State<'_, AppState>,
    id: String,
) -> Result<(), String> {
    let vault = VAULT.lock().unwrap();
    
    if !vault.is_unlocked {
        return Err("Vault is locked".to_string());
    }
    
    let connection = vault.connection.as_ref().ok_or("No connection")?;
    
    vault::increment_use_count(connection, &id)
}

// Conversion from Credential to CredentialDto
impl From<Credential> for CredentialDto {
    fn from(c: Credential) -> Self {
        Self {
            id: c.id,
            title: c.title,
            username: c.username,
            password: c.password,
            url_pattern: c.url_pattern,
            notes: c.notes,
            totp_secret: c.totp_secret,
            favorite: c.favorite,
        }
    }
}
