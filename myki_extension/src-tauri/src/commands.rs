//! Tauri commands for Myki Desktop
//! Bridges the frontend to the unified Myki Core Rust library.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::{State, AppHandle, Manager};
use myki_core::{VaultDatabase, Credential, derive_key};

/// Application state containing the active vault database and current configuration.
pub struct AppState {
    /// Active vault database connection. None if the vault is locked.
    pub db: Mutex<Option<VaultDatabase>>,
    /// Path to the vault database file.
    pub db_path: Mutex<PathBuf>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            db: Mutex::new(None),
            db_path: Mutex::new(PathBuf::new()),
        }
    }
}

/// DTO for communicating credential data to the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDto {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub favorite: bool,
}

impl From<Credential> for CredentialDto {
    fn from(c: Credential) -> Self {
        Self {
            id: c.id,
            title: c.title,
            username: c.username,
            password: c.password,
            url: c.url,
            notes: c.notes,
            favorite: c.favorite,
        }
    }
}

/// Setup desktop app paths.
#[tauri::command]
pub async fn setup_desktop(app_handle: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    let mut db_path = state.db_path.lock().unwrap();
    if db_path.to_str().map(|s| s.is_empty()).unwrap_or(true) {
        let app_data = app_handle.path().app_data_dir().map_err(|e| e.to_string())?;
        std::fs::create_dir_all(&app_data).map_err(|e| e.to_string())?;
        *db_path = app_data.join("vault.db");
    }
    Ok(())
}

/// Create a new vault.
#[tauri::command]
pub async fn create_vault(
    state: State<'_, AppState>,
    password: String,
) -> Result<(), String> {
    let db_path = state.db_path.lock().unwrap().clone();
    if db_path.exists() {
        return Err("Vault already exists".to_string());
    }

    let salt = myki_core::crypto::generate_salt();
    let master_key = derive_key(&password, &salt, &Default::default())
        .map_err(|e| e.to_string())?;

    let db = VaultDatabase::create(db_path.to_str().unwrap(), &master_key)
        .map_err(|e| e.to_string())?;
    
    // Store the salt in the vault_meta table for future unlocks
    let salt_b64 = myki_core::crypto::encode_base64(&salt);
    db.set_meta("salt", &salt_b64).map_err(|e| e.to_string())?;
    
    let mut active_db = state.db.lock().unwrap();
    *active_db = Some(db);
    
    Ok(())
}

/// Unlock an existing vault.
#[tauri::command]
pub async fn unlock_vault(
    state: State<'_, AppState>,
    password: String,
) -> Result<(), String> {
    let db_path = state.db_path.lock().unwrap().clone();
    if !db_path.exists() {
        return Err("Vault not found".to_string());
    }

    // Connect to database temporarily to get salt
    let conn = rusqlite::Connection::open(&db_path)
        .map_err(|e| format!("Failed to open database: {}", e))?;
    
    let mut stmt = conn.prepare("SELECT value FROM vault_meta WHERE key = 'salt'")
        .map_err(|e| e.to_string())?;
    let salt_b64: String = stmt.query_row([], |row| row.get(0))
        .map_err(|_| "Vault salt not found. The database might be corrupted or not a Myki vault.".to_string())?;
    
    let salt = myki_core::crypto::decode_base64(&salt_b64)
        .map_err(|e| format!("Invalid salt format: {}", e))?;

    let master_key = derive_key(&password, &salt, &Default::default())
        .map_err(|e| e.to_string())?;

    let db = VaultDatabase::open(db_path.to_str().unwrap(), &master_key)
        .map_err(|e| e.to_string())?;
    
    let mut active_db = state.db.lock().unwrap();
    *active_db = Some(db);
    
    Ok(())
}

/// Lock the vault and clear it from memory.
#[tauri::command]
pub async fn lock_vault(state: State<'_, AppState>) -> Result<(), String> {
    let mut db = state.db.lock().unwrap();
    *db = None;
    Ok(())
}

/// Check if the vault is unlocked.
#[tauri::command]
pub async fn is_vault_unlocked(state: State<'_, AppState>) -> Result<bool, String> {
    let db = state.db.lock().unwrap();
    Ok(db.is_some())
}

/// Get all credentials.
#[tauri::command]
pub async fn get_all_credentials(state: State<'_, AppState>) -> Result<Vec<CredentialDto>, String> {
    let db_guard = state.db.lock().unwrap();
    let db = db_guard.as_ref().ok_or("Vault is locked")?;
    
    let creds = db.get_all_credentials().map_err(|e| e.to_string())?;
    Ok(creds.into_iter().map(CredentialDto::from).collect())
}

/// Search for credentials.
#[tauri::command]
pub async fn search_credentials(state: State<'_, AppState>, query: String) -> Result<Vec<CredentialDto>, String> {
    let db_guard = state.db.lock().unwrap();
    let db = db_guard.as_ref().ok_or("Vault is locked")?;
    
    let creds = db.search_credentials(&query).map_err(|e| e.to_string())?;
    Ok(creds.into_iter().map(CredentialDto::from).collect())
}

/// Add a new credential.
#[tauri::command]
pub async fn add_credential(
    state: State<'_, AppState>,
    title: String,
    username: String,
    password: String,
    url: Option<String>,
    notes: Option<String>,
) -> Result<CredentialDto, String> {
    let db_guard = state.db.lock().unwrap();
    let db = db_guard.as_ref().ok_or("Vault is locked")?;
    
    let mut cred = Credential::new(title, username, password);
    cred.url = url;
    cred.notes = notes;
    
    db.save_credential(&cred).map_err(|e| e.to_string())?;
    Ok(CredentialDto::from(cred))
}

/// Delete a credential.
#[tauri::command]
pub async fn delete_credential(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let db_guard = state.db.lock().unwrap();
    let db = db_guard.as_ref().ok_or("Vault is locked")?;
    
    db.delete_credential(&id).map_err(|e| e.to_string())?;
    Ok(())
}

/// Generate a secure password.
#[tauri::command]
pub fn generate_password(length: usize) -> String {
    // Basic implementation using myki_core primitives if available, 
    // or just a simple random string for now.
    let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
    let mut pwd = String::new();
    for _ in 0..length {
        let idx = rand::random::<usize>() % charset.len();
        pwd.push(charset.chars().nth(idx).unwrap());
    }
    pwd
}

