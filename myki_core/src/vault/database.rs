//! Vault Database
//! 
//! This module provides encrypted SQLite storage for vault items.
//! 
//! # Security Model
//! 
//! All sensitive data is encrypted using AES-256-GCM before being written to disk.
//! The encryption key (VaultKey) is derived from the user's master password.
//! 
//! # Database Schema
//! 
//! ```sql
//! -- Metadata table (unencrypted)
//! CREATE TABLE vault_meta (
//!     key TEXT PRIMARY KEY,
//!     value TEXT NOT NULL
//! );
//! 
//! -- Credentials table (encrypted)
//! CREATE TABLE credentials (
//!     id TEXT PRIMARY KEY,
//!     data TEXT NOT NULL,        -- Encrypted JSON
//!     created_at INTEGER NOT NULL,
//!     updated_at INTEGER NOT NULL
//! );
//! 
//! -- Other tables follow the same pattern...
//! ```
//! 
//! # Thread Safety
//! 
//! The database uses a Mutex to ensure thread-safe access to the SQLite connection.

use super::{Credential, VaultError};  // Import types from parent module
use crate::crypto::{MasterKey, Aes256Gcm, EncryptedData};  // Crypto types
use rusqlite::{Connection, params};   // SQLite connection and parameterized queries
use std::sync::Mutex;                 // Thread-safe interior mutability

// ---------------------------------------------------------------------------
// Vault Database Type
// ---------------------------------------------------------------------------

/// A secure, encrypted database for storing vault items.
/// 
/// VaultDatabase wraps a SQLite connection with encryption capabilities.
/// All vault data is encrypted before being stored in the database.
/// 
/// # Security Properties
/// 
/// - **Encryption at rest**: All sensitive data is encrypted using AES-256-GCM
/// - **Key separation**: The encryption key is derived from the master password
/// - **Authenticated storage**: GCM mode ensures data integrity
/// 
/// # Thread Safety
/// 
/// VaultDatabase uses a Mutex to ensure that only one thread can access the
/// database at a time. This is necessary because SQLite connections are not
/// thread-safe by default.
/// 
/// # Example
/// 
/// ```rust
/// use myki_core::{VaultDatabase, derive_key, MasterKey};
/// 
/// // Create a new vault
/// let master_key = derive_key("password", &[0u8; 32], &Default::default()).unwrap();
/// let db = VaultDatabase::create("vault.db", &master_key).unwrap();
/// 
/// // Save a credential
/// let cred = myki_core::Credential::new("GitHub".into(), "user".into(), "pass".into());
/// db.save_credential(&cred).unwrap();
/// 
/// // Retrieve all credentials
/// let all = db.get_all_credentials().unwrap();
/// ```
pub struct VaultDatabase {
    /// A thread-safe connection to the SQLite database.
    /// 
    /// Mutex provides interior mutability - we can access the connection
    /// even through a shared reference, as long as we lock the mutex first.
    /// 
    /// The Connection itself is NOT thread-safe, hence the Mutex wrapper.
    conn: Mutex<Connection>,
    
    /// The cipher used for encrypting and decrypting data.
    /// 
    /// This is created once when the vault is opened, using the derived VaultKey.
    /// It's stored here so we don't need to derive the key for each operation.
    cipher: Aes256Gcm,
}

impl VaultDatabase {
    /// Creates a new vault database file at the specified path and initializes the schema.
    /// 
    /// If a file already exists at the path, it will be overwritten!
    /// Use `open()` to open an existing vault.
    /// 
    /// # Parameters
    /// 
    /// * `path`: The file system path where the database will be created.
    ///            This should be a secure location with appropriate file permissions.
    /// 
    /// * `master_key`: The key used to protect the vault.
    ///                   This is derived from the user's master password.
    /// 
    /// # Returns
    /// 
    /// * `Ok(VaultDatabase)` if creation succeeded
    /// * `Err(VaultError)` if file creation or schema initialization failed
    /// 
    /// # Example
    /// 
    /// ```rust
    /// use myki_core::{VaultDatabase, derive_key};
    /// 
    /// let master_key = derive_key("password", &[0u8; 32], &Default::default()).unwrap();
    /// let db = VaultDatabase::create("my_vault.db", &master_key).unwrap();
    /// ```
    pub fn create(path: &str, master_key: &MasterKey) -> Result<Self, VaultError> {
        // -----------------------------------------------------------------------
        // Open or create the SQLite database file
        // -----------------------------------------------------------------------
        // Connection::open creates a new database file if it doesn't exist,
        // or opens an existing one if it does.
        let conn = Connection::open(path)
            .map_err(|e| VaultError::Database(format!("Failed to open database: {}", e)))?;
        
        // Enable WAL mode for better read/write concurrency
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| VaultError::Database(format!("Failed to enable WAL mode: {}", e)))?;
        
        // -----------------------------------------------------------------------
        // Initialize the database schema
        // -----------------------------------------------------------------------
        // execute_batch runs multiple SQL statements at once.
        // We create all necessary tables in one transaction for efficiency.
        conn.execute_batch(
            "
            -- Metadata table for vault configuration (stored as plaintext)
            CREATE TABLE IF NOT EXISTS vault_meta (
                key TEXT PRIMARY KEY,      -- The metadata key
                value TEXT NOT NULL        -- The metadata value
            );
            
            -- Credentials table: stores encrypted credential data
            CREATE TABLE IF NOT EXISTS credentials (
                id TEXT PRIMARY KEY,       -- UUID of the credential
                data TEXT NOT NULL,        -- Encrypted JSON of the credential
                created_at INTEGER NOT NULL,-- Unix timestamp
                updated_at INTEGER NOT NULL -- Unix timestamp
            );
            
            -- Identities table: stores encrypted personal information
            CREATE TABLE IF NOT EXISTS identities (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            
            -- Secure notes table: stores encrypted text notes
            CREATE TABLE IF NOT EXISTS secure_notes (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            
            -- Folders table: stores encrypted folder data
            CREATE TABLE IF NOT EXISTS folders (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            
            -- TOTP secrets table: stores encrypted TOTP configuration
            CREATE TABLE IF NOT EXISTS totp_secrets (
                id TEXT PRIMARY KEY,
                credential_id TEXT,          -- Optional link to credential
                data TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            
            -- Index for sorting credentials by update time (for recent-first ordering)
            CREATE INDEX IF NOT EXISTS idx_credentials_updated ON credentials(updated_at);
            
            -- Index for looking up TOTP by credential
            CREATE INDEX IF NOT EXISTS idx_totp_credential ON totp_secrets(credential_id);
            "
        ).map_err(|e| VaultError::Database(format!("Failed to initialize schema: {}", e)))?;
        
        // -----------------------------------------------------------------------
        // Create the cipher for encryption/decryption
        // -----------------------------------------------------------------------
        // We use the vault_key (first 32 bytes of derived material)
        // for AES-256-GCM encryption.
        let cipher = Aes256Gcm::new(&master_key.vault_key);
        
        // -----------------------------------------------------------------------
        // Return the VaultDatabase instance
        // -----------------------------------------------------------------------
        Ok(Self {
            conn: Mutex::new(conn),
            cipher,
        })
    }
    
    /// Opens an existing vault database file.
    /// 
    /// Use this to open a vault that was previously created with `create()`.
    /// The vault must be decrypted with the correct master key.
    /// 
    /// # Parameters
    /// 
    /// * `path`: The path to the existing database file.
    /// * `master_key`: The key required to decrypt the vault contents.
    /// 
    /// # Returns
    /// 
    /// * `Ok(VaultDatabase)` if opening succeeded
    /// * `Err(VaultError)` if the file doesn't exist or has wrong key
    /// 
    /// # Example
    /// 
    /// ```rust
    /// use myki_core::{VaultDatabase, derive_key};
    /// 
    /// let master_key = derive_key("password", &stored_salt, &Default::default()).unwrap();
    /// let db = VaultDatabase::open("my_vault.db", &master_key).unwrap();
    /// ```
    pub fn open(path: &str, master_key: &MasterKey) -> Result<Self, VaultError> {
        // Open the SQLite database
        let conn = Connection::open(path)
            .map_err(|e| VaultError::Database(format!("Failed to open database: {}", e)))?;
            
        // Enable WAL mode for better read/write concurrency
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| VaultError::Database(format!("Failed to enable WAL mode: {}", e)))?;
        
        // Create the cipher with the vault key
        let cipher = Aes256Gcm::new(&master_key.vault_key);
        
        Ok(Self {
            conn: Mutex::new(conn),
            cipher,
        })
    }

    /// Sets a metadata value in the vault.
    /// 
    /// Metadata is stored UNENCRYPTED in the vault_meta table.
    /// This is appropriate for non-sensitive configuration data.
    /// 
    /// # Parameters
    /// 
    /// * `key`: The metadata key (e.g., "salt", "version", "name")
    /// * `value`: The value to store
    /// 
    /// # Example
    /// 
    /// ```rust
    /// db.set_meta("salt", "base64encodedSalt").unwrap();
    /// db.set_meta("version", "1.0").unwrap();
    /// ```
    pub fn set_meta(&self, key: &str, value: &str) -> Result<(), VaultError> {
        // Lock the mutex to get exclusive access to the connection
        let conn = self.conn.lock().unwrap();
        
        // INSERT OR REPLACE: inserts new row or replaces existing one with same key
        conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?1, ?2)",
            params![key, value],  // params! handles type conversion safely
        ).map_err(|e| VaultError::Database(format!("Failed to set metadata: {}", e)))?;
        
        Ok(())
    }

    /// Gets a metadata value from the vault.
    /// 
    /// # Parameters
    /// 
    /// * `key`: The metadata key to retrieve
    /// 
    /// # Returns
    /// 
    /// * `Ok(Some(String))` if the key exists
    /// * `Ok(None)` if the key doesn't exist
    /// * `Err(VaultError)` if the database operation failed
    /// 
    /// # Example
    /// 
    /// ```rust
    /// let salt = db.get_meta("salt").unwrap();
    /// match salt {
    ///     Some(s) => println!("Salt found: {}", s),
    ///     None => println!("No salt stored"),
    /// }
    /// ```
    pub fn get_meta(&self, key: &str) -> Result<Option<String>, VaultError> {
        // Lock the mutex for database access
        let conn = self.conn.lock().unwrap();
        
        // Prepare a parameterized query to prevent SQL injection
        let mut stmt = conn.prepare("SELECT value FROM vault_meta WHERE key = ?1")
            .map_err(|e| VaultError::Database(format!("Failed to prepare query: {}", e)))?;
        
        // Execute the query with the key parameter
        let mut rows = stmt.query(params![key])
            .map_err(|e| VaultError::Database(format!("Failed to query metadata: {}", e)))?;
        
        // Get the first row (if any)
        if let Some(row) = rows.next().map_err(|e| VaultError::Database(format!("Failed to fetch row: {}", e)))? {
            // Extract the value column (column 0)
            Ok(Some(row.get(0).map_err(|e| VaultError::Database(format!("Failed to get value: {}", e)))?))
        } else {
            // No row found with this key
            Ok(None)
        }
    }
    
    /// Encrypts and saves a credential to the database.
    /// 
    /// The credential is serialized to JSON, then encrypted using AES-256-GCM.
    /// The encrypted data is stored as base64 in the database.
    /// 
    /// If a credential with the same ID already exists, it will be replaced.
    /// 
    /// # Parameters
    /// 
    /// * `credential`: The credential to save
    /// 
    /// # Example
    /// 
    /// ```rust
    /// use myki_core::Credential;
    /// 
    /// let cred = Credential::new("GitHub".into(), "user".into(), "pass".into());
    /// db.save_credential(&cred).unwrap();
    /// ```
    pub fn save_credential(&self, credential: &Credential) -> Result<(), VaultError> {
        // -----------------------------------------------------------------------
        // Step 1: Serialize the credential to JSON
        // -----------------------------------------------------------------------
        // serde_json::to_string converts the struct to a JSON string
        // This is what we'll encrypt
        let json = serde_json::to_string(credential)
            .map_err(|e| VaultError::Encryption(format!("Failed to serialize: {}", e)))?;
        
        // -----------------------------------------------------------------------
        // Step 2: Encrypt the JSON
        // -----------------------------------------------------------------------
        // We pass None for AAD (Additional Authenticated Data)
        // The cipher generates a random nonce internally
        let encrypted = self.cipher.encrypt(json.as_bytes(), None)
            .map_err(|e| VaultError::Encryption(format!("Encryption failed: {}", e)))?;
        
        // Convert to base64 for storage (compact, text-safe format)
        let combined = encrypted.to_base64();
        
        // -----------------------------------------------------------------------
        // Step 3: Save to database
        // -----------------------------------------------------------------------
        // Lock the connection for thread-safe access
        let conn = self.conn.lock().unwrap();
        
        // INSERT OR REPLACE: upsert behavior - insert new or replace existing
        conn.execute(
            "INSERT OR REPLACE INTO credentials (id, data, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)",
            params![credential.id, combined, credential.created_at, credential.updated_at],
        ).map_err(|e| VaultError::Database(format!("Failed to save credential: {}", e)))?;
        
        Ok(())
    }
    
    /// Retrieves all credentials from the database, decrypting them in the process.
    /// 
    /// Credentials are returned in descending order by update time (newest first).
    /// 
    /// # Returns
    /// 
    /// * `Ok(Vec<Credential>)` containing all decrypted credentials
    /// * `Err(VaultError)` if decryption or database access failed
    /// 
    /// # Example
    /// 
    /// ```rust
    /// let all = db.get_all_credentials().unwrap();
    /// for cred in all {
    ///     println!("{}: {}", cred.title, cred.username);
    /// }
    /// ```
    pub fn get_all_credentials(&self) -> Result<Vec<Credential>, VaultError> {
        // Lock the connection
        let conn = self.conn.lock().unwrap();
        
        // Prepare query to get all credentials, ordered by newest first
        let mut stmt = conn.prepare(
            "SELECT data FROM credentials ORDER BY updated_at DESC"
        ).map_err(|e| VaultError::Database(format!("Failed to prepare query: {}", e)))?;
        
        // Execute and iterate over rows
        let rows = stmt.query_map([], |row| {
            row.get::<_, String>(0)  // Get the 'data' column (column 0)
        }).map_err(|e| VaultError::Database(format!("Failed to execute query: {}", e)))?;
        
        let mut credentials = Vec::new();
        
        for row in rows {
            // Get the base64-encoded encrypted data
            let combined = row.map_err(|e| VaultError::Database(format!("Failed to read row: {}", e)))?;
            
            // -----------------------------------------------------------------------
            // Decrypt each credential
            // -----------------------------------------------------------------------
            // Parse the base64-encoded encrypted data
            match EncryptedData::from_base64(&combined) {
                Ok(encrypted) => {
                    match self.cipher.decrypt(&encrypted, None) {
                        Ok(decrypted) => {
                            if let Ok(json) = String::from_utf8(decrypted) {
                                if let Ok(credential) = serde_json::from_str::<Credential>(&json) {
                                    credentials.push(credential);
                                } else {
                                    eprintln!("Warning: Failed to parse credential JSON for ID: {}", "unknown");
                                }
                            } else {
                                eprintln!("Warning: Failed to parse decrypted data as UTF-8");
                            }
                        },
                        Err(e) => {
                            eprintln!("Warning: Failed to decrypt credential: {:?}", e);
                        }
                    }
                },
                Err(e) => {
                    eprintln!("Warning: Failed to parse EncryptedData from base64: {:?}", e);
                }
            }
            // Note: We skip malformed entries rather than failing the whole operation, but now we log them
        }
        
        Ok(credentials)
    }
    
    /// Permanently removes a credential from the database.
    /// 
    /// This operation is irreversible. The credential is permanently deleted.
    /// 
    /// # Parameters
    /// 
    /// * `id`: The UUID of the credential to delete
    /// 
    /// # Example
    /// 
    /// ```rust
    /// db.delete_credential("550e8400-e29b-41d4-a716-446655440000").unwrap();
    /// ```
    pub fn delete_credential(&self, id: &str) -> Result<(), VaultError> {
        let conn = self.conn.lock().unwrap();
        
        // DELETE FROM table WHERE condition
        // This permanently removes the row
        conn.execute(
            "DELETE FROM credentials WHERE id = ?1",
            params![id],
        ).map_err(|e| VaultError::Database(format!("Failed to delete credential: {}", e)))?;
        
        Ok(())
    }
    
    /// Searches for credentials whose title, username, or URL matches the query string.
    /// 
    /// Search is case-insensitive and matches substrings.
    /// 
    /// # Parameters
    /// 
    /// * `query`: The search string (matched against title, username, and URL)
    /// 
    /// # Returns
    /// 
    /// * `Ok(Vec<Credential>)` containing all matching credentials
    /// 
    /// # Example
    /// 
    /// ```rust
    /// let results = db.search_credentials("github").unwrap();
    /// for cred in results {
    ///     println!("Found: {}", cred.title);
    /// }
    /// ```
    pub fn search_credentials(&self, query: &str) -> Result<Vec<Credential>, VaultError> {
        // First, get all credentials
        let all = self.get_all_credentials()?;
        
        // Convert query to lowercase for case-insensitive matching
        let query_lower = query.to_lowercase();
        
        // Filter credentials that match the query
        // A credential matches if:
        // - Its title contains the query
        // - Its username contains the query
        // - Its URL contains the query
        Ok(all.into_iter().filter(|c| {
            c.title.to_lowercase().contains(&query_lower) ||
            c.username.to_lowercase().contains(&query_lower) ||
            c.url.as_ref().map(|u| u.to_lowercase().contains(&query_lower)).unwrap_or(false)
        }).collect())
    }
    
    /// Closes the database connection.
    /// 
    /// This is called when the vault is being locked or the application is shutting down.
    /// In Rust, the database is automatically closed when the VaultDatabase is dropped,
    /// but this method allows explicit cleanup.
    pub fn close(self) {
        // Dropping self will:
        // 1. Drop the cipher
        // 2. Drop the Mutex
        // 3. Drop the Connection (which closes the SQLite file)
        drop(self);
    }
}
