//! Vault Database
//! 
//! Encrypted SQLite vault storage

use super::{Credential, VaultError};
use crate::crypto::{MasterKey, Aes256Gcm, EncryptedData};
use rusqlite::{Connection, params};
use std::sync::Mutex;

/// A secure, encrypted database for storing vault items.
/// 
/// This uses SQLite as the storage engine, but all sensitive data is encrypted
/// using AES-256-GCM before being saved to the disk.
pub struct VaultDatabase {
    /// A thread-safe connection to the SQLite database.
    conn: Mutex<Connection>,
    /// The cipher used for encrypting and decrypting data.
    cipher: Aes256Gcm,
}

impl VaultDatabase {
    /// Creates a new vault database file at the specified path and initializes the schema.
    /// 
    /// # Parameters
    /// - `path`: The file system path where the database will be created.
    /// - `master_key`: The key used to protect the vault.
    pub fn create(path: &str, master_key: &MasterKey) -> Result<Self, VaultError> {
        let conn = Connection::open(path)
            .map_err(|e| VaultError::Database(e.to_string()))?;
        
        // Initialize schema
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS vault_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            
            CREATE TABLE IF NOT EXISTS credentials (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            
            CREATE TABLE IF NOT EXISTS identities (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            
            CREATE TABLE IF NOT EXISTS secure_notes (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            
            CREATE TABLE IF NOT EXISTS folders (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            
            CREATE TABLE IF NOT EXISTS totp_secrets (
                id TEXT PRIMARY KEY,
                credential_id TEXT,
                data TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            
            CREATE INDEX IF NOT EXISTS idx_credentials_updated ON credentials(updated_at);
            CREATE INDEX IF NOT EXISTS idx_totp_credential ON totp_secrets(credential_id);
            "
        ).map_err(|e| VaultError::Database(e.to_string()))?;
        
        let cipher = Aes256Gcm::new(&master_key.vault_key);
        
        Ok(Self {
            conn: Mutex::new(conn),
            cipher,
        })
    }
    
    /// Opens an existing vault database file.
    /// 
    /// # Parameters
    /// - `path`: The path to the existing database file.
    /// - `master_key`: The key required to decrypt the vault contents.
    pub fn open(path: &str, master_key: &MasterKey) -> Result<Self, VaultError> {
        let conn = Connection::open(path)
            .map_err(|e| VaultError::Database(e.to_string()))?;
        
        let cipher = Aes256Gcm::new(&master_key.vault_key);
        
        Ok(Self {
            conn: Mutex::new(conn),
            cipher,
        })
    }

    /// Sets a metadata value in the vault.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<(), VaultError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?1, ?2)",
            params![key, value],
        ).map_err(|e| VaultError::Database(e.to_string()))?;
        Ok(())
    }

    /// Gets a metadata value from the vault.
    pub fn get_meta(&self, key: &str) -> Result<Option<String>, VaultError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT value FROM vault_meta WHERE key = ?1")
            .map_err(|e| VaultError::Database(e.to_string()))?;
        
        let mut rows = stmt.query(params![key])
            .map_err(|e| VaultError::Database(e.to_string()))?;
        
        if let Some(row) = rows.next().map_err(|e| VaultError::Database(e.to_string()))? {
            Ok(Some(row.get(0).map_err(|e| VaultError::Database(e.to_string()))?))
        } else {
            Ok(None)
        }
    }
    
    /// Encrypts and saves a credential to the database.
    /// 
    /// If a credential with the same ID already exists, it will be replaced.
    pub fn save_credential(&self, credential: &Credential) -> Result<(), VaultError> {
        let json = serde_json::to_string(credential)
            .map_err(|e| VaultError::Encryption(e.to_string()))?;
        
        let encrypted = self.cipher.encrypt(json.as_bytes(), None)
            .map_err(|e| VaultError::Encryption(e.to_string()))?;
        
        let combined = encrypted.to_base64();
        
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO credentials (id, data, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)",
            params![credential.id, combined, credential.created_at, credential.updated_at],
        ).map_err(|e| VaultError::Database(e.to_string()))?;
        
        Ok(())
    }
    
    /// Retrieves all credentials from the database, decrypting them in the process.
    /// 
    /// # Returns
    /// - A list of decrypted `Credential` objects, sorted by their last update time.
    pub fn get_all_credentials(&self) -> Result<Vec<Credential>, VaultError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT data FROM credentials ORDER BY updated_at DESC"
        ).map_err(|e| VaultError::Database(e.to_string()))?;
        
        let rows = stmt.query_map([], |row| {
            row.get::<_, String>(0)
        }).map_err(|e| VaultError::Database(e.to_string()))?;
        
        let mut credentials = Vec::new();
        for row in rows {
            let combined = row.map_err(|e| VaultError::Database(e.to_string()))?;
            
            // Parse encrypted data
            if let Ok(encrypted) = EncryptedData::from_base64(&combined) {
                if let Ok(decrypted) = self.cipher.decrypt(&encrypted, None) {
                    if let Ok(json) = String::from_utf8(decrypted) {
                        if let Ok(credential) = serde_json::from_str::<Credential>(&json) {
                            credentials.push(credential);
                        }
                    }
                }
            }
        }
        
        Ok(credentials)
    }
    
    /// Permanently removes a credential from the database.
    pub fn delete_credential(&self, id: &str) -> Result<(), VaultError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM credentials WHERE id = ?1",
            params![id],
        ).map_err(|e| VaultError::Database(e.to_string()))?;
        Ok(())
    }
    
    /// Searches for credentials whose title, username, or URL matches the query string.
    pub fn search_credentials(&self, query: &str) -> Result<Vec<Credential>, VaultError> {
        let all = self.get_all_credentials()?;
        let query_lower = query.to_lowercase();
        
        Ok(all.into_iter().filter(|c| {
            c.title.to_lowercase().contains(&query_lower) ||
            c.username.to_lowercase().contains(&query_lower) ||
            c.url.as_ref().map(|u| u.to_lowercase().contains(&query_lower)).unwrap_or(false)
        }).collect())
    }
    
    /// Closes the database connection.
    pub fn close(self) {
        drop(self);
    }
}
