//! Vault management for Myki Extension
//! Handles encrypted storage and retrieval of credentials

#![allow(dead_code)]
#![allow(clippy::too_many_arguments)]

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::LazyLock;
use uuid::Uuid;

use crate::crypto::{decrypt, encrypt, MasterKey};

/// Vault state
#[derive(Default)]
pub struct Vault {
    pub is_unlocked: bool,
    pub connection: Option<Connection>,
    pub master_key: Option<MasterKey>,
}

#[allow(clippy::derivable_impls)]
impl Vault {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Global vault instance
pub static VAULT: LazyLock<std::sync::Mutex<Vault>> = LazyLock::new(|| std::sync::Mutex::new(Vault::default()));

/// Credential entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url_pattern: Option<String>,
    pub notes: Option<String>,
    pub totp_secret: Option<String>,
    pub folder_id: Option<String>,
    pub favorite: bool,
    pub created_at: i64,
    pub updated_at: i64,
    pub use_count: i32,
}

/// Vault status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultStatus {
    pub exists: bool,
    pub is_unlocked: bool,
    pub credential_count: i32,
}

/// Initialize vault database
pub fn init_vault(db_path: &Path) -> Result<(), String> {
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS vault_config (
            id INTEGER PRIMARY KEY,
            salt BLOB NOT NULL,
            password_hash BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )",
        [],
    )
    .map_err(|e| e.to_string())?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS credentials (
            id TEXT PRIMARY KEY,
            title_encrypted BLOB NOT NULL,
            username_encrypted BLOB NOT NULL,
            password_encrypted BLOB NOT NULL,
            url_pattern TEXT,
            notes_encrypted BLOB,
            totp_secret_encrypted BLOB,
            folder_id TEXT,
            favorite INTEGER DEFAULT 0,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            use_count INTEGER DEFAULT 0
        )",
        [],
    )
    .map_err(|e| e.to_string())?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS folders (
            id TEXT PRIMARY KEY,
            name_encrypted BLOB NOT NULL,
            parent_id TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )",
        [],
    )
    .map_err(|e| e.to_string())?;

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_credentials_url ON credentials(url_pattern)",
        [],
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}

/// Create new vault with master password
pub fn create_vault(db_path: &Path, password: &str) -> Result<(), String> {
    // Check if vault already exists
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;
    
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM vault_config)",
            [],
            |row| row.get(0),
        )
        .unwrap_or(false);

    if exists {
        return Err("Vault already exists".to_string());
    }

    // Derive master key
    let master_key = MasterKey::derive(password, None).map_err(|e| e.to_string())?;

    // Generate verification hash
    let password_hash = crate::crypto::hash(&master_key.as_bytes());

    // Store config
    conn.execute(
        "INSERT INTO vault_config (salt, password_hash, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)",
        params![
            &master_key.salt(),
            &password_hash,
            chrono_now(),
            chrono_now()
        ],
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}

/// Unlock vault with password
pub fn unlock_vault(db_path: &Path, password: &str) -> Result<MasterKey, String> {
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;

    // Get stored salt and hash
    let (salt, stored_hash): ([u8; 16], [u8; 32]) = conn
        .query_row(
            "SELECT salt, password_hash FROM vault_config LIMIT 1",
            [],
            |row| {
                let salt: Vec<u8> = row.get(0)?;
                let hash: Vec<u8> = row.get(1)?;
                Ok((
                    salt.try_into().unwrap_or([0u8; 16]),
                    hash.try_into().unwrap_or([0u8; 32]),
                ))
            },
        )
        .map_err(|e| e.to_string())?;

    // Derive key and verify
    let master_key = MasterKey::derive(password, Some(salt)).map_err(|e| e.to_string())?;
    let computed_hash = crate::crypto::hash(&master_key.as_bytes());

    if computed_hash != stored_hash {
        return Err("Invalid password".to_string());
    }

    Ok(master_key)
}

/// Add credential to vault
pub fn add_credential(
    conn: &Connection,
    master_key: &MasterKey,
    title: &str,
    username: &str,
    password: &str,
    url_pattern: Option<&str>,
    notes: Option<&str>,
    totp_secret: Option<&str>,
) -> Result<Credential, String> {
    let id = Uuid::new_v4().to_string();
    let now = chrono_now();

    // Encrypt sensitive fields
    let title_encrypted = encrypt(title.as_bytes(), &master_key.as_bytes())
        .map_err(|e| e.to_string())?;
    let username_encrypted = encrypt(username.as_bytes(), &master_key.as_bytes())
        .map_err(|e| e.to_string())?;
    let password_encrypted = encrypt(password.as_bytes(), &master_key.as_bytes())
        .map_err(|e| e.to_string())?;
    let notes_encrypted = notes
        .map(|n| encrypt(n.as_bytes(), &master_key.as_bytes()))
        .transpose()
        .map_err(|e| e.to_string())?;
    let totp_encrypted = totp_secret
        .map(|t| encrypt(t.as_bytes(), &master_key.as_bytes()))
        .transpose()
        .map_err(|e| e.to_string())?;

    conn.execute(
        "INSERT INTO credentials (id, title_encrypted, username_encrypted, password_encrypted, 
         url_pattern, notes_encrypted, totp_secret_encrypted, created_at, updated_at) 
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            id,
            title_encrypted,
            username_encrypted,
            password_encrypted,
            url_pattern,
            notes_encrypted,
            totp_encrypted,
            now,
            now
        ],
    )
    .map_err(|e| e.to_string())?;

    Ok(Credential {
        id,
        title: title.to_string(),
        username: username.to_string(),
        password: password.to_string(),
        url_pattern: url_pattern.map(|s| s.to_string()),
        notes: notes.map(|s| s.to_string()),
        totp_secret: totp_secret.map(|s| s.to_string()),
        folder_id: None,
        favorite: false,
        created_at: now,
        updated_at: now,
        use_count: 0,
    })
}

/// Get credentials for URL
pub fn get_credentials_for_url(
    conn: &Connection,
    master_key: &MasterKey,
    url: &str,
) -> Result<Vec<Credential>, String> {
    // Extract domain from URL
    let domain = extract_domain(url);
    
    // Search for matching credentials
    let mut stmt = conn
        .prepare(
            "SELECT id, title_encrypted, username_encrypted, password_encrypted, 
             url_pattern, notes_encrypted, totp_secret_encrypted, folder_id, 
             favorite, created_at, updated_at, use_count 
             FROM credentials 
             WHERE url_pattern LIKE ?1 OR url_pattern LIKE ?2",
        )
        .map_err(|e| e.to_string())?;

    let pattern1 = format!("%{}%", domain);
    let pattern2 = format!("%{}%", url);

    let credentials = stmt
        .query_map(params![pattern1, pattern2], |row| {
            decrypt_row(row, master_key)
        })
        .map_err(|e| e.to_string())?;

    credentials.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
}

/// Search credentials
pub fn search_credentials(
    conn: &Connection,
    master_key: &MasterKey,
    query: &str,
) -> Result<Vec<Credential>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT id, title_encrypted, username_encrypted, password_encrypted, 
             url_pattern, notes_encrypted, totp_secret_encrypted, folder_id, 
             favorite, created_at, updated_at, use_count 
             FROM credentials",
        )
        .map_err(|e| e.to_string())?;

    let credentials = stmt
        .query_map([], |row| {
            decrypt_row(row, master_key)
        })
        .map_err(|e| e.to_string())?;

    let all_credentials: Vec<Credential> = credentials
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;

    // Filter by search query
    let query_lower = query.to_lowercase();
    Ok(all_credentials
        .into_iter()
        .filter(|c| {
            c.title.to_lowercase().contains(&query_lower)
                || c.username.to_lowercase().contains(&query_lower)
                || c.url_pattern
                    .as_ref()
                    .map(|u| u.to_lowercase().contains(&query_lower))
                    .unwrap_or(false)
        })
        .collect())
}

/// Delete credential
pub fn delete_credential(conn: &Connection, id: &str) -> Result<(), String> {
    conn.execute("DELETE FROM credentials WHERE id = ?1", params![id])
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Update credential
pub fn update_credential(
    conn: &Connection,
    master_key: &MasterKey,
    id: &str,
    title: &str,
    username: &str,
    password: &str,
    url_pattern: Option<&str>,
    notes: Option<&str>,
) -> Result<(), String> {
    let now = chrono_now();

    let title_encrypted = encrypt(title.as_bytes(), &master_key.as_bytes())
        .map_err(|e| e.to_string())?;
    let username_encrypted = encrypt(username.as_bytes(), &master_key.as_bytes())
        .map_err(|e| e.to_string())?;
    let password_encrypted = encrypt(password.as_bytes(), &master_key.as_bytes())
        .map_err(|e| e.to_string())?;
    let notes_encrypted = notes
        .map(|n| encrypt(n.as_bytes(), &master_key.as_bytes()))
        .transpose()
        .map_err(|e| e.to_string())?;

    conn.execute(
        "UPDATE credentials SET title_encrypted = ?1, username_encrypted = ?2, 
         password_encrypted = ?3, url_pattern = ?4, notes_encrypted = ?5, 
         updated_at = ?6 WHERE id = ?7",
        params![
            title_encrypted,
            username_encrypted,
            password_encrypted,
            url_pattern,
            notes_encrypted,
            now,
            id
        ],
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}

/// Increment credential use count
pub fn increment_use_count(conn: &Connection, id: &str) -> Result<(), String> {
    conn.execute(
        "UPDATE credentials SET use_count = use_count + 1 WHERE id = ?1",
        params![id],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Get vault status
pub fn get_vault_status(db_path: &Path) -> Result<VaultStatus, String> {
    if !db_path.exists() {
        return Ok(VaultStatus {
            exists: false,
            is_unlocked: false,
            credential_count: 0,
        });
    }

    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;
    
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM vault_config)",
            [],
            |row| row.get(0),
        )
        .unwrap_or(false);

    let count: i32 = conn
        .query_row(
            "SELECT COUNT(*) FROM credentials",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let vault = VAULT.lock().unwrap();

    Ok(VaultStatus {
        exists,
        is_unlocked: vault.is_unlocked,
        credential_count: count,
    })
}

/// Check if vault exists
pub fn vault_exists(db_path: &Path) -> bool {
    if !db_path.exists() {
        return false;
    }

    Connection::open(db_path)
        .and_then(|conn| {
            conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM vault_config)",
                [],
                |row| row.get(0),
            )
        })
        .unwrap_or(false)
}

/// Helper to get current timestamp
fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Extract domain from URL
fn extract_domain(url: &str) -> String {
    url.parse::<url::Url>()
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_else(|| url.to_string())
}

/// Helper to decrypt a credential row
fn decrypt_row(
    row: &rusqlite::Row,
    master_key: &MasterKey,
) -> rusqlite::Result<Credential> {
    let id: String = row.get(0)?;
    let title_encrypted: Vec<u8> = row.get(1)?;
    let username_encrypted: Vec<u8> = row.get(2)?;
    let password_encrypted: Vec<u8> = row.get(3)?;
    let url_pattern: Option<String> = row.get(4)?;
    let notes_encrypted: Option<Vec<u8>> = row.get(5)?;
    let totp_encrypted: Option<Vec<u8>> = row.get(6)?;
    let folder_id: Option<String> = row.get(7)?;
    let favorite: i32 = row.get(8)?;
    let created_at: i64 = row.get(9)?;
    let updated_at: i64 = row.get(10)?;
    let use_count: i32 = row.get(11)?;

    let title = decrypt(&title_encrypted, &master_key.as_bytes())
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default();
    let username = decrypt(&username_encrypted, &master_key.as_bytes())
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default();
    let password = decrypt(&password_encrypted, &master_key.as_bytes())
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default();
    let notes = notes_encrypted
        .and_then(|e| decrypt(&e, &master_key.as_bytes()).ok())
        .map(|b| String::from_utf8_lossy(&b).to_string());
    let totp_secret = totp_encrypted
        .and_then(|e| decrypt(&e, &master_key.as_bytes()).ok())
        .map(|b| String::from_utf8_lossy(&b).to_string());

    Ok(Credential {
        id,
        title,
        username,
        password,
        url_pattern,
        notes,
        totp_secret,
        folder_id,
        favorite: favorite != 0,
        created_at,
        updated_at,
        use_count,
    })
}

