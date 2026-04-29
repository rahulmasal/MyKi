//! Vault Database
//! 
//! Encrypted SQLite vault storage

use super::{Credential, VaultError};
use crate::crypto::{MasterKey, Aes256Gcm, EncryptedData};
use rusqlite::{Connection, params};
use std::sync::Mutex;

/// Encrypted vault database
pub struct VaultDatabase {
    conn: Mutex<Connection>,
    cipher: Aes256Gcm,
}

impl VaultDatabase {
    /// Create a new vault
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
    
    /// Open an existing vault
    pub fn open(path: &str, master_key: &MasterKey) -> Result<Self, VaultError> {
        let conn = Connection::open(path)
            .map_err(|e| VaultError::Database(e.to_string()))?;
        
        let cipher = Aes256Gcm::new(&master_key.vault_key);
        
        Ok(Self {
            conn: Mutex::new(conn),
            cipher,
        })
    }
    
    /// Save a credential
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
    
    /// Get all credentials
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
    
    /// Delete a credential
    pub fn delete_credential(&self, id: &str) -> Result<(), VaultError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM credentials WHERE id = ?1",
            params![id],
        ).map_err(|e| VaultError::Database(e.to_string()))?;
        Ok(())
    }
    
    /// Search credentials by title or username
    pub fn search_credentials(&self, query: &str) -> Result<Vec<Credential>, VaultError> {
        let all = self.get_all_credentials()?;
        let query_lower = query.to_lowercase();
        
        Ok(all.into_iter().filter(|c| {
            c.title.to_lowercase().contains(&query_lower) ||
            c.username.to_lowercase().contains(&query_lower) ||
            c.url.as_ref().map(|u| u.to_lowercase().contains(&query_lower)).unwrap_or(false)
        }).collect())
    }
    
    /// Close the database
    pub fn close(self) {
        drop(self);
    }
}
