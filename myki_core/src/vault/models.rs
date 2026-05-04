//! Vault Models
//! 
//! This module defines the data structures used to store credentials and other
//! sensitive information in the vault.
//! 
//! # Data Types
//! 
//! - Credential: Username/password entries (most common)
//! - Identity: Personal information (addresses, phone numbers, etc.)
//! - SecureNote: Encrypted free-form text notes
//! - Folder: Organization containers
//! - TotpSecret: Two-factor authentication configuration
//! 
//! # Serialization
//! 
//! All models implement serde's Serialize and Deserialize traits,
//! allowing them to be converted to/from JSON for storage.
//! 
//! # Example
//! 
//! ```rust
//! use myki_core::Credential;
//! 
//! let cred = Credential::new(
//!     "GitHub".to_string(),
//!     "user@email.com".to_string(),
//!     "secretpassword".to_string(),
//! );
//! 
//! // Serialize to JSON
//! let json = serde_json::to_string(&cred).unwrap();
//! ```

use serde::{Deserialize, Serialize};  // Serialization traits for JSON storage
use uuid::Uuid;                      // For generating unique IDs

// ---------------------------------------------------------------------------
// Credential Model
// ---------------------------------------------------------------------------

/// Represents a complete credential entry in the vault.
/// 
/// A credential is a username/password pair associated with a service or website.
/// It may also include URLs, notes, tags, and TOTP secrets for 2FA.
/// 
/// # Example JSON Representation
/// 
/// ```json
/// {
///   "id": "550e8400-e29b-41d4-a716-446655440000",
///   "title": "GitHub",
///   "username": "user@email.com",
///   "password": "secretpassword",
///   "url": "https://github.com/login",
///   "notes": "Work account",
///   "folder_id": null,
///   "tags": ["work", "code"],
///   "favorite": true,
///   "created_at": 1609459200,
///   "updated_at": 1609459200,
///   "last_used_at": 1609462800,
///   "use_count": 5,
///   "attachments": null
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]  // Debug for debugging, Clone for copying, Serialize/Deserialize for JSON
pub struct Credential {
    /// Unique identifier for the credential (UUID v4).
    /// 
    /// This is generated randomly and should be globally unique.
    /// Used to reference this credential in the database.
    pub id: String,
    
    /// A user-friendly title for the entry (e.g., "GitHub", "My Bank").
    /// 
    /// This is the primary way users identify credentials in the UI.
    pub title: String,
    
    /// The username or email associated with the account.
    /// 
    /// This is typically what's entered in the "username" field of a login form.
    pub username: String,
    
    /// The secret password for the account.
    /// 
    /// IMPORTANT: This is stored encrypted in the database (via the VaultDatabase),
    /// never in plaintext. The plaintext is only available when the vault is unlocked.
    pub password: String,
    
    /// Optional URL for the service's login page.
    /// 
    /// This is used for auto-fill functionality in browsers/extensions.
    /// May include the full login URL or just the domain.
    pub url: Option<String>,
    
    /// Optional free-form notes.
    /// 
    /// Users can store additional information here:
    /// - Security questions/answers
    /// - Account recovery information
    /// - Any other relevant details
    pub notes: Option<String>,
    
    /// Optional ID of the folder this credential belongs to.
    /// 
    /// If None, the credential is at the root level.
    /// Use this to organize credentials into categories.
    pub folder_id: Option<String>,
    
    /// A list of tags for searching and organization.
    /// 
    /// Tags are user-defined labels like "work", "personal", "important", etc.
    /// They provide an alternative way to categorize credentials.
    pub tags: Vec<String>,
    
    /// Whether this credential is marked as a favorite.
    /// 
    /// Favorites appear at the top of the credential list for quick access.
    pub favorite: bool,
    
    /// Unix timestamp of when the entry was created.
    /// 
    /// Seconds since 1970-01-01 00:00:00 UTC.
    /// Set automatically when creating a new credential.
    pub created_at: i64,
    
    /// Unix timestamp of the last time the entry was modified.
    /// 
    /// Updated automatically whenever any field is changed.
    /// Used to sort credentials by recent activity.
    pub updated_at: i64,
    
    /// Unix timestamp of when the credential was last used for auto-fill.
    /// 
    /// Set when the user copies the password or uses auto-fill.
    /// Used to show "recently used" credentials.
    pub last_used_at: Option<i64>,
    
    /// The number of times this credential has been used/viewed.
    /// 
    /// Incremented each time the user copies the password
    /// or uses auto-fill functionality.
    pub use_count: i64,
    
    /// Optional list of secure file attachment IDs or paths.
    /// 
    /// Allows attaching files (documents, images, etc.) to credentials.
    /// Files themselves are stored encrypted elsewhere; this just stores references.
    pub attachments: Option<Vec<String>>,
}

impl Credential {
    /// Creates a new `Credential` with a unique ID and current timestamps.
    /// 
    /// This is the recommended way to create new credentials.
    /// All optional fields default to None/empty, and timestamps are set automatically.
    /// 
    /// # Example
    /// 
    /// ```rust
    /// use myki_core::Credential;
    /// 
    /// let cred = Credential::new(
    ///     "GitHub".to_string(),
    ///     "user@email.com".to_string(),
    ///     "password123".to_string(),
    /// );
    /// ```
    pub fn new(title: String, username: String, password: String) -> Self {
        // Get current Unix timestamp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        Self {
            // Generate a new UUID for this credential
            id: Uuid::new_v4().to_string(),
            title,
            username,
            password,
            url: None,           // Optional - set later if needed
            notes: None,         // Optional - set later if needed
            folder_id: None,     // Root level by default
            tags: Vec::new(),    // No tags initially
            favorite: false,     // Not a favorite by default
            created_at: now,      // Set creation time
            updated_at: now,      // Same as created_at initially
            last_used_at: None,   // Never used yet
            use_count: 0,        // Never used yet
            attachments: None,    // No attachments
        }
    }
    
    /// Creates a new `Credential` with optional fields like URL and notes.
    /// 
    /// This is useful when you have all the information at once.
    /// 
    /// # Example
    /// 
    /// ```rust
    /// use myki_core::Credential;
    /// 
    /// let cred = Credential::new_full(
    ///     "GitHub".to_string(),
    ///     "user@email.com".to_string(),
    ///     "password123".to_string(),
    ///     Some("https://github.com".to_string()),
    ///     Some("Work account".to_string()),
    /// );
    /// ```
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

// ---------------------------------------------------------------------------
// CredentialNew Model
// ---------------------------------------------------------------------------

/// A structure used for creating new credentials, providing optional fields.
/// 
/// This is an alternative constructor pattern that allows all fields to be optional.
/// It's useful for:
/// - User registration forms where fields may be empty
/// - Importing credentials where not all fields are present
/// - API endpoints where optional fields use Option
/// 
/// # Conversion
/// 
/// CredentialNew implements `From<CredentialNew> for Credential`,
/// allowing easy conversion with: `let cred: Credential = credential_new.into();`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialNew {
    /// Required: Display title for the credential
    pub title: String,
    
    /// Required: Username for the account
    pub username: String,
    
    /// Required: The password
    pub password: String,
    
    /// Optional: Website URL
    pub url: Option<String>,
    
    /// Optional: Additional notes
    pub notes: Option<String>,
    
    /// Optional: Folder ID for organization
    pub folder_id: Option<String>,
    
    /// Optional: List of tags
    pub tags: Option<Vec<String>>,
    
    /// Optional: Mark as favorite
    pub favorite: Option<bool>,
    
    /// Optional: List of attachment IDs
    pub attachments: Option<Vec<String>>,
}

impl From<CredentialNew> for Credential {
    /// Converts a `CredentialNew` request into a full `Credential` object.
    /// 
    /// This is a convenience method for API handlers. It:
    /// 1. Creates a new Credential using the required fields
    /// 2. Sets optional fields with sensible defaults
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

// ---------------------------------------------------------------------------
// Identity Model
// ---------------------------------------------------------------------------

/// Represents personal information entries (like address or email) in the vault.
/// 
/// Identities are used to store personal details that might be used for:
/// - Auto-fill forms (name, email, phone, address)
/// - Multiple identities (personal, work, etc.)
/// - Storing sensitive personal information securely
/// 
/// # Example
/// 
/// ```rust
/// use myki_core::Identity;
/// 
/// let identity = Identity::new("Personal Info".to_string());
/// // Then set fields as needed:
/// // identity.first_name = Some("John".to_string());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    /// Unique identifier (UUID)
    pub id: String,
    
    /// User-friendly title (e.g., "John Doe", "Home Address")
    pub title: String,
    
    /// First name
    pub first_name: Option<String>,
    
    /// Last name
    pub last_name: Option<String>,
    
    /// Email address
    pub email: Option<String>,
    
    /// Phone number
    pub phone: Option<String>,
    
    /// Physical address
    pub address: Option<String>,
    
    /// Creation timestamp
    pub created_at: i64,
    
    /// Last modified timestamp
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

// ---------------------------------------------------------------------------
// SecureNote Model
// ---------------------------------------------------------------------------

/// A simple text entry for storing sensitive notes.
/// 
/// Secure notes are encrypted free-form text. They're useful for:
/// - API keys or tokens
/// - Recovery codes
/// - Software license keys
/// - Any sensitive text you want to keep secure
/// 
/// # Example
/// 
/// ```rust
/// use myki_core::SecureNote;
/// 
/// let note = SecureNote::new(
///     "Recovery Codes".to_string(),
///     "12345678\n87654321\n...".to_string(),
/// );
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureNote {
    /// Unique identifier (UUID)
    pub id: String,
    
    /// User-friendly title
    pub title: String,
    
    /// The encrypted note content
    pub content: String,
    
    /// Optional folder ID for organization
    pub folder_id: Option<String>,
    
    /// Creation timestamp
    pub created_at: i64,
    
    /// Last modified timestamp
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

// ---------------------------------------------------------------------------
// Folder Model
// ---------------------------------------------------------------------------

/// A container used for organizing other vault items.
/// 
/// Folders can contain:
/// - Credentials
/// - Identities
/// - Secure Notes
/// 
/// Folders can also be nested (parent_id references another folder).
/// 
/// # Example
/// 
/// ```rust
/// use myki_core::Folder;
/// 
/// // Create a root folder
/// let work = Folder::new("Work".to_string());
/// 
/// // Create a nested folder
/// let projects = Folder::new("Projects".to_string());
/// // projects.parent_id = Some(work.id);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Folder {
    /// Unique identifier (UUID)
    pub id: String,
    
    /// Folder name
    pub name: String,
    
    /// Parent folder ID (None for root folders)
    pub parent_id: Option<String>,
    
    /// Creation timestamp
    pub created_at: i64,
    
    /// Last modified timestamp
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
            parent_id: None,  // Root folder by default
            created_at: now,
            updated_at: now,
        }
    }
}

// ---------------------------------------------------------------------------
// TotpSecret Model
// ---------------------------------------------------------------------------

/// Stores the secret key and configuration for a TOTP generator.
/// 
/// TOTP secrets are associated with credentials that have two-factor authentication enabled.
/// 
/// # Security Note
/// 
/// The secret field is stored encrypted in the vault, just like passwords.
/// 
/// # Example
/// 
/// ```rust
/// use myki_core::TotpSecret;
/// 
/// // Create with Base32-encoded secret from 2FA setup
/// let totp = TotpSecret::new("GEZDGNBVGY3TQOJQ".to_string());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpSecret {
    /// Unique identifier (UUID)
    pub id: String,
    
    /// ID of the credential this TOTP is associated with
    pub credential_id: Option<String>,
    
    /// Base32-encoded TOTP secret
    /// 
    /// This is the shared secret generated during 2FA setup.
    /// It's encoded in Base32 for easier handling (QR codes, etc.).
    pub secret: String,
    
    /// Hashing algorithm ("SHA1", "SHA256", or "SHA512")
    pub algorithm: String,
    
    /// Number of digits in the code (typically 6)
    pub digits: u8,
    
    /// Time period in seconds (typically 30)
    pub period: u64,
    
    /// The service issuer (e.g., "GitHub", "Google")
    /// 
    /// This is typically extracted from the QR code URI during setup.
    pub issuer: Option<String>,
    
    /// Creation timestamp
    pub created_at: i64,
    
    /// Last modified timestamp
    pub updated_at: i64,
}

impl TotpSecret {
    /// Creates a new `TotpSecret` with default RFC 6238 settings.
    /// 
    /// Default values:
    /// - Algorithm: SHA1 (most common)
    /// - Digits: 6 (standard)
    /// - Period: 30 seconds (standard)
    /// 
    /// # Example
    /// 
    /// ```rust
    /// use myki_core::TotpSecret;
    /// 
    /// let totp = TotpSecret::new("SECRET123".to_string());
    /// ```
    pub fn new(secret: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        Self {
            id: Uuid::new_v4().to_string(),
            credential_id: None,
            secret,
            algorithm: "SHA1".to_string(),  // Default algorithm
            digits: 6,                       // Default digits
            period: 30,                      // Default period (seconds)
            issuer: None,
            created_at: now,
            updated_at: now,
        }
    }
}
