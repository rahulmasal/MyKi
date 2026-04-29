//! Vault Models
//! 
//! Data structures for vault items

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Credential entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub folder_id: Option<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_used_at: Option<i64>,
    pub use_count: i64,
}

impl Credential {
    /// Create a new credential
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
        }
    }
    
    /// Create with all fields
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

/// New credential (for creation)
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
}

impl From<CredentialNew> for Credential {
    fn from(new: CredentialNew) -> Self {
        let mut cred = Credential::new(new.title, new.username, new.password);
        cred.url = new.url;
        cred.notes = new.notes;
        cred.folder_id = new.folder_id;
        cred.tags = new.tags.unwrap_or_default();
        cred.favorite = new.favorite.unwrap_or(false);
        cred
    }
}

/// Identity entry (personal info)
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
    /// Create a new identity
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

/// Secure note entry
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
    /// Create a new secure note
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

/// Folder for organizing items
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Folder {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Folder {
    /// Create a new folder
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

/// TOTP secret
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
    /// Create a new TOTP secret
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
