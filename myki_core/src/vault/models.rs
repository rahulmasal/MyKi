//! Vault Models
//! 
//! Data structures for vault items

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Represents a complete credential entry in the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    /// Unique identifier for the credential (UUID).
    pub id: String,
    /// A user-friendly title for the entry (e.g., "Google Account").
    pub title: String,
    /// The username or email associated with the account.
    pub username: String,
    /// The plaintext password (encrypted when stored in the database).
    pub password: String,
    /// Optional URL for the service's login page.
    pub url: Option<String>,
    /// Optional free-form notes.
    pub notes: Option<String>,
    /// Optional ID of the folder this credential belongs to.
    pub folder_id: Option<String>,
    /// A list of tags for searching and organization.
    pub tags: Vec<String>,
    /// Whether this credential is marked as a favorite.
    pub favorite: bool,
    /// Unix timestamp of when the entry was created.
    pub created_at: i64,
    /// Unix timestamp of the last time the entry was modified.
    pub updated_at: i64,
    /// Unix timestamp of when the credential was last used.
    pub last_used_at: Option<i64>,
    /// The number of times this credential has been used/viewed.
    pub use_count: i64,
    /// Optional list of secure file attachment IDs or paths.
    pub attachments: Option<Vec<String>>,
}

impl Credential {
    /// Creates a new `Credential` with a unique ID and current timestamps.
    pub fn new(title: String, username: String, password: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        Self {
            id: Uuid::new_v4().to_string(),
            title,
            username,
            password,
            url: None,
            notes: None,
            folder_id: None,
            tags: Vec::new(),
            favorite: false,
            created_at: now,
            updated_at: now,
            last_used_at: None,
            use_count: 0,
            attachments: None,
        }
    }
    
    /// Creates a new `Credential` with optional fields like URL and notes.
    pub fn new_full(
        title: String,
        username: String,
        password: String,
        url: Option<String>,
        notes: Option<String>,
    ) -> Self {
        let mut cred = Self::new(title, username, password);
        cred.url = url;
        cred.notes = notes;
        cred
    }
}

/// A structure used for creating new credentials, providing optional fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialNew {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub folder_id: Option<String>,
    pub tags: Option<Vec<String>>,
    pub favorite: Option<bool>,
    pub attachments: Option<Vec<String>>,
}

impl From<CredentialNew> for Credential {
    /// Converts a `CredentialNew` request into a full `Credential` object.
    fn from(new: CredentialNew) -> Self {
        let mut cred = Credential::new(new.title, new.username, new.password);
        cred.url = new.url;
        cred.notes = new.notes;
        cred.folder_id = new.folder_id;
        cred.tags = new.tags.unwrap_or_default();
        cred.favorite = new.favorite.unwrap_or(false);
        cred.attachments = new.attachments;
        cred
    }
}

/// Represents personal information entries (like address or email) in the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub id: String,
    pub title: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub address: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Identity {
    /// Creates a new `Identity` with a unique ID.
    pub fn new(title: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        Self {
            id: Uuid::new_v4().to_string(),
            title,
            first_name: None,
            last_name: None,
            email: None,
            phone: None,
            address: None,
            created_at: now,
            updated_at: now,
        }
    }
}

/// A simple text entry for storing sensitive notes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureNote {
    pub id: String,
    pub title: String,
    pub content: String,
    pub folder_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl SecureNote {
    /// Creates a new `SecureNote` with a unique ID.
    pub fn new(title: String, content: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        Self {
            id: Uuid::new_v4().to_string(),
            title,
            content,
            folder_id: None,
            created_at: now,
            updated_at: now,
        }
    }
}

/// A container used for organizing other vault items.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Folder {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Folder {
    /// Creates a new `Folder` with a unique ID.
    pub fn new(name: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            parent_id: None,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Stores the secret key and configuration for a TOTP generator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpSecret {
    pub id: String,
    pub credential_id: Option<String>,
    pub secret: String,
    pub algorithm: String,
    pub digits: u8,
    pub period: u64,
    pub issuer: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl TotpSecret {
    /// Creates a new `TotpSecret` with default RFC 6238 settings (SHA1, 6 digits, 30s).
    pub fn new(secret: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        Self {
            id: Uuid::new_v4().to_string(),
            credential_id: None,
            secret,
            algorithm: "SHA1".to_string(),
            digits: 6,
            period: 30,
            issuer: None,
            created_at: now,
            updated_at: now,
        }
    }
}
