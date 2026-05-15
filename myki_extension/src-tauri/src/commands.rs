//! Tauri commands for Myki Desktop
//! Bridges the frontend to the unified Myki Core Rust library.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::{State, AppHandle, Manager};
use myki_core::{VaultDatabase, Credential, CredentialMeta, derive_key};
use tracing;

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

/// Lightweight DTO for list/search — excludes password and notes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialMetaDto {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: Option<String>,
    pub favorite: bool,
}

impl From<CredentialMeta> for CredentialMetaDto {
    fn from(m: CredentialMeta) -> Self {
        Self {
            id: m.id,
            title: m.title,
            username: m.username,
            url: m.url,
            favorite: m.favorite,
        }
    }
}

/// Setup desktop app paths.
#[tauri::command]
pub async fn setup_desktop(app_handle: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    let mut db_path = state.db_path.lock().unwrap();
    if db_path.to_str().map(|s| s.is_empty()).unwrap_or(true) {
        let app_data = app_handle.path().app_data_dir().map_err(|e| {
            tracing::error!("Failed to get app data dir: {}", e);
            e.to_string()
        })?;
        std::fs::create_dir_all(&app_data).map_err(|e| {
            tracing::error!("Failed to create app data dir: {}", e);
            e.to_string()
        })?;
        *db_path = app_data.join("vault.db");
    }
    tracing::info!("Desktop setup complete, vault path: {:?}", *db_path);
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
        tracing::error!("Vault creation failed: already exists at {:?}", db_path);
        return Err("Vault already exists".to_string());
    }

    let db = VaultDatabase::create_new(db_path.to_str().unwrap(), &password)
        .map_err(|e| {
            tracing::error!("Database creation failed: {}", e);
            e.to_string()
        })?;

    let mut active_db = state.db.lock().unwrap();
    *active_db = Some(db);

    tracing::info!("Vault created at {:?}", db_path);
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
        tracing::error!("Unlock failed: vault not found at {:?}", db_path);
        return Err("Vault not found".to_string());
    }

    let conn = rusqlite::Connection::open(&db_path)
        .map_err(|e| {
            tracing::error!("Failed to open database for unlock: {}", e);
            format!("Failed to open database: {}", e)
        })?;
    
    let mut stmt = conn.prepare("SELECT value FROM vault_meta WHERE key = 'salt'")
        .map_err(|e| {
            tracing::error!("Failed to prepare salt query: {}", e);
            e.to_string()
        })?;
    let salt_b64: String = stmt.query_row([], |row| row.get(0))
        .map_err(|_| {
            tracing::error!("Salt not found in vault metadata");
            "Vault salt not found. The database might be corrupted or not a Myki vault.".to_string()
        })?;
    
    let salt = myki_core::crypto::decode_base64(&salt_b64)
        .map_err(|e| {
            tracing::error!("Invalid salt encoding: {}", e);
            format!("Invalid salt format: {}", e)
        })?;

    let master_key = derive_key(&password, &salt, &Default::default())
        .map_err(|e| {
            tracing::error!("Key derivation failed during unlock: {}", e);
            e.to_string()
        })?;

    let db = VaultDatabase::open(db_path.to_str().unwrap(), &master_key)
        .map_err(|e| {
            tracing::error!("Failed to open vault (wrong password?): {}", e);
            e.to_string()
        })?;
    
    let mut active_db = state.db.lock().unwrap();
    *active_db = Some(db);
    
    tracing::info!("Vault unlocked successfully");
    Ok(())
}

/// Get the vault database file path.
#[tauri::command]
pub fn get_vault_path(state: State<'_, AppState>) -> String {
    state.db_path.lock().unwrap().to_string_lossy().to_string()
}

/// Check if a vault database file exists on disk.
#[tauri::command]
pub fn vault_exists(state: State<'_, AppState>) -> bool {
    let db_path = state.db_path.lock().unwrap();
    db_path.exists()
}

/// Lock the vault and clear it from memory.
#[tauri::command]
pub async fn lock_vault(state: State<'_, AppState>) -> Result<(), String> {
    let mut db = state.db.lock().unwrap();
    *db = None;
    tracing::info!("Vault locked");
    Ok(())
}

/// Check if the vault is unlocked.
#[tauri::command]
pub async fn is_vault_unlocked(state: State<'_, AppState>) -> Result<bool, String> {
    let db = state.db.lock().unwrap();
    Ok(db.is_some())
}

/// Get all credentials (metadata only — no password/notes).
#[tauri::command]
pub async fn get_all_credentials(state: State<'_, AppState>) -> Result<Vec<CredentialMetaDto>, String> {
    let db_guard = state.db.lock().unwrap();
    let db = db_guard.as_ref().ok_or_else(|| {
        tracing::error!("get_all_credentials failed: vault is locked");
        "Vault is locked".to_string()
    })?;

    let metas = db.get_all_credential_metas().map_err(|e| {
        tracing::error!("Failed to get all credentials: {}", e);
        e.to_string()
    })?;
    Ok(metas.into_iter().map(CredentialMetaDto::from).collect())
}

/// Search credentials (metadata only — no password/notes).
#[tauri::command]
pub async fn search_credentials(state: State<'_, AppState>, query: String) -> Result<Vec<CredentialMetaDto>, String> {
    let db_guard = state.db.lock().unwrap();
    let db = db_guard.as_ref().ok_or_else(|| {
        tracing::error!("search_credentials failed: vault is locked");
        "Vault is locked".to_string()
    })?;

    let metas = db.search_credential_metas(&query).map_err(|e| {
        tracing::error!("Search failed for '{}': {}", query, e);
        e.to_string()
    })?;
    Ok(metas.into_iter().map(CredentialMetaDto::from).collect())
}

/// Get the decrypted password for a single credential by ID.
#[tauri::command]
pub async fn get_credential_password(state: State<'_, AppState>, id: String) -> Result<String, String> {
    let db_guard = state.db.lock().unwrap();
    let db = db_guard.as_ref().ok_or_else(|| {
        tracing::error!("get_credential_password failed: vault is locked");
        "Vault is locked".to_string()
    })?;

    db.get_credential_password(&id).map_err(|e| {
        tracing::error!("Failed to get password for {}: {}", id, e);
        e.to_string()
    })
}

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
    let db = db_guard.as_ref().ok_or_else(|| {
        tracing::error!("add_credential failed: vault is locked");
        "Vault is locked".to_string()
    })?;
    
    let mut cred = Credential::new(title.clone(), username, password);
    cred.url = url;
    cred.notes = notes;
    
    db.save_credential(&cred).map_err(|e| {
        tracing::error!("Failed to save credential '{}': {}", title, e);
        e.to_string()
    })?;
    tracing::info!("Credential added: {}", title);
    Ok(CredentialDto::from(cred))
}

#[tauri::command]
pub async fn delete_credential(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let db_guard = state.db.lock().unwrap();
    let db = db_guard.as_ref().ok_or_else(|| {
        tracing::error!("delete_credential failed: vault is locked");
        "Vault is locked".to_string()
    })?;
    
    db.delete_credential(&id).map_err(|e| {
        tracing::error!("Failed to delete credential {}: {}", id, e);
        e.to_string()
    })?;
    tracing::info!("Credential deleted: {}", id);
    Ok(())
}

/// Generate a secure password.
#[tauri::command]
pub fn generate_password(length: usize) -> String {
    use rand::Rng;
    let charset: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
    let mut rng = rand::thread_rng();
    let pwd: String = (0..length)
        .map(|_| charset[rng.gen_range(0..charset.len())] as char)
        .collect();
    tracing::info!("Generated password of length {}", length);
    pwd
}

