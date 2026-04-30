//! Vault management for Myki Extension
//! Handles encrypted storage and retrieval of credentials using SQLite.

#![allow(dead_code)]
#![allow(clippy::too_many_arguments)]

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::LazyLock;
use uuid::Uuid;

use crate::crypto::{decrypt, encrypt, MasterKey};

/// Represents the current runtime state of the vault.
///
/// This includes the active database connection and the master key needed
/// for decryption, but only while the vault is unlocked.
#[derive(Default)]
pub struct Vault {
    /// Whether the vault is currently accessible.
    pub is_unlocked: bool,
    /// Persistent connection to the SQLite database.
    pub connection: Option<Connection>,
    /// The master key derived from the password, kept in memory for decryption.
    pub master_key: Option<MasterKey>,
}

#[allow(clippy::derivable_impls)]
impl Vault {
    /// Creates a new, locked vault instance.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Global, thread-safe vault instance accessible across the application.
pub static VAULT: LazyLock<std::sync::Mutex<Vault>> = LazyLock::new(|| std::sync::Mutex::new(Vault::default()));

/// A single credential entry as it appears to the frontend.
///
/// All fields are decrypted before being placed in this struct.
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

/// High-level overview of the vault's state for the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultStatus {
    /// True if the database file exists and is initialized.
    pub exists: bool,
    /// True if the vault is currently unlocked in memory.
    pub is_unlocked: bool,
    /// Total number of credentials stored.
    pub credential_count: i32,
}

/// Initializes the vault database schema if it doesn't already exist.
///
/// Creates tables for:
/// - `vault_config`: Global settings and password verification.
/// - `credentials`: Encrypted storage for passwords.
/// - `folders`: Organization for credentials.
pub fn init_vault(db_path: &Path) -> Result<(), String> {
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;

    // Store salt and master key hash for password verification
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

    // Main table for credentials. Sensitive data is stored as encrypted BLOBs.
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

    // Index for fast URL matching
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_credentials_url ON credentials(url_pattern)",
        [],
    )
    .map_err(|e| e.to_string())?;

    Ok(())
}

/// Creates a new vault database and sets the initial master password.
///
/// # Arguments
/// * `db_path` - Location to create the SQLite file.
/// * `password` - The master password chosen by the user.
pub fn create_vault(db_path: &Path, password: &str) -> Result<(), String> {
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;
    
    // Safety check: Don't overwrite an existing vault
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

    // Derive the master key and store the hash for future verification
    let master_key = MasterKey::derive(password, None).map_err(|e| e.to_string())?;
    let password_hash = crate::crypto::hash(&master_key.as_bytes());

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

/// Verifies the master password and returns the derived MasterKey.
pub fn unlock_vault(db_path: &Path, password: &str) -> Result<MasterKey, String> {
    let conn = Connection::open(db_path).map_err(|e| e.to_string())?;

    // Retrieve the salt and hash stored during creation
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

    // Derive a key with the attempt password
    let master_key = MasterKey::derive(password, Some(salt)).map_err(|e| e.to_string())?;
    let computed_hash = crate::crypto::hash(&master_key.as_bytes());

    // Security: Only return the key if the hashes match
    if computed_hash != stored_hash {
        return Err("Invalid password".to_string());
    }

    Ok(master_key)
}

/// Adds a new credential record to the database.
///
/// This function handles the encryption of all sensitive fields before they
/// touch the disk.
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

    // Encrypt sensitive fields using the master key (AES-256-GCM)
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

/// Retrieves and decrypts credentials that match the provided URL.
pub fn get_credentials_for_url(
    conn: &Connection,
    master_key: &MasterKey,
    url: &str,
) -> Result<Vec<Credential>, String> {
    let domain = extract_domain(url);
    
    // Query database for potential matches
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

    // Iterate through results and decrypt each row
    let credentials = stmt
        .query_map(params![pattern1, pattern2], |row| {
            decrypt_row(row, master_key)
        })
        .map_err(|e| e.to_string())?;

    credentials.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
}

/// Searches all credentials and returns those that match the query.
pub fn search_credentials(
    conn: &Connection,
    master_key: &MasterKey,
    query: &str,
) -> Result<Vec<Credential>, String> {
    // Note: Since data is encrypted, we have to fetch all and filter in memory,
    // or store unencrypted searchable fields. Here we fetch and decrypt all.
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

/// Permanently deletes a credential by its ID.
pub fn delete_credential(conn: &Connection, id: &str) -> Result<(), String> {
    conn.execute("DELETE FROM credentials WHERE id = ?1", params![id])
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Updates an existing credential with new information.
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

    // Re-encrypt all fields
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

/// Increments the usage counter for a credential.
pub fn increment_use_count(conn: &Connection, id: &str) -> Result<(), String> {
    conn.execute(
        "UPDATE credentials SET use_count = use_count + 1 WHERE id = ?1",
        params![id],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Checks the database to see if it exists and how many items it contains.
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

/// Simple check for vault existence.
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

// Helper to get current timestamp in milliseconds
fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// Extract domain from URL (e.g., 'https://google.com/search' -> 'google.com')
fn extract_domain(url: &str) -> String {
    url.parse::<url::Url>()
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_else(|| url.to_string())
}

// Internal helper to decrypt all fields of a database row and convert to a Credential struct
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


