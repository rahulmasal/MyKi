//! Foreign Function Interface (FFI) for Myki Core
//! 
//! This module provides C-compatible functions that can be called from other programming languages,
//! particularly Dart/Flutter via the dart:ffi extension. The FFI allows non-Rust code to use
//! Myki's cryptographic operations without implementing them itself.
//! 
//! # Function Naming Convention
//! All exported functions are prefixed with "myki_" to avoid namespace collisions.
//! 
//! # Memory Management
//! Strings returned via output parameters must be freed by the caller using myki_free_string().
//! Failure to do so will cause memory leaks.
//! 
//! # Error Handling
//! Functions return FfiError codes rather than throwing exceptions, as exceptions don't
//! cross FFI boundaries reliably.

use std::ffi::{CStr, CString};  // CStr: borrowed C string, CString: owned C string with null terminator
use std::os::raw::c_char;        // c_char is i8 or c_char on most platforms (C's char type)
use crate::crypto::{derive_key, Aes256Gcm, VaultKey};  // Import cryptographic functions from our crate
use base64::Engine as _;        // Import base64 encoder/decoder (the _ imports only the trait, not the function)

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Error codes returned by FFI functions to indicate success or specific failure types.
/// 
/// These values MUST match the Dart-side enum FfiError in rust_bridge_service.dart.
/// The numeric values are part of the ABI contract between Rust and Dart.
/// 
/// # Note
/// When adding new error codes, always append them at the end to maintain backward compatibility
/// with existing callers.
#[repr(C)]  // Ensure the enum has a predictable memory layout for FFI
pub enum FfiError {
    /// Operation completed successfully. Value: 0
    Success = 0,
    
    /// Provided string was null or contained invalid UTF-8.
    /// This usually means the caller passed an invalid pointer or didn't encode properly.
    InvalidString = 1,
    
    /// Failed to derive a key from the password and salt.
    /// This can happen if Argon2id fails (rare) or parameters are invalid.
    DerivationFailed = 2,
    
    /// Encryption operation failed.
    /// This can happen if the key is invalid or internal AES-GCM error occurs.
    EncryptionFailed = 3,
    
    /// Decryption operation failed.
    /// This can happen if ciphertext is corrupted, wrong key, or authentication tag mismatch.
    DecryptionFailed = 4,
    
    /// The provided key was invalid (e.g., wrong length).
    /// AES-256 requires exactly 32 bytes for the key.
    InvalidKey = 5,
}

// ---------------------------------------------------------------------------
// Key Derivation Function (FFI)
// ---------------------------------------------------------------------------

/// Derives a 256-bit vault key from a password and a base64-encoded salt.
/// 
/// This is the primary entry point for password-based key derivation. It uses the Argon2id
/// algorithm, which is designed to be resistant to GPU-based cracking attacks by requiring
/// a significant amount of memory and CPU time.
/// 
/// # Parameters
/// 
/// * `password`: Pointer to a null-terminated C string containing the user's master password.
///               Must not be null.
/// 
/// * `salt`: Pointer to a null-terminated C string containing a base64-encoded random salt.
///            The salt should be at least 16 bytes (32 characters when base64-encoded).
///            Must not be null.
/// 
/// * `out_key_b64`: Pointer to a pointer that will receive the base64-encoded derived key.
///                   On success, this will point to a newly allocated string that MUST be
///                   freed by the caller using `myki_free_string`.
/// 
/// # Returns
/// 
/// * `FfiError::Success` (0) if the operation succeeded
/// * `FfiError::InvalidString` if password or salt are null or invalid UTF-8
/// * `FfiError::DerivationFailed` if key derivation itself failed
/// 
/// # Example (Dart usage)
/// 
/// ```dart
/// final result = _deriveKey(password, saltB64);
/// if (result == 0) {
///   final key = pOutKey.value.toDartString();
///   _freeString(pOutKey.value);
/// }
/// ```
#[no_mangle]  // Tell Rust not to mangle this function name - required for FFI
#[allow(clippy::not_unsafe_ptr_arg_deref)]  // We're being careful with null checks, suppress the lint
pub extern "C" fn myki_derive_key(
    // Input: Pointer to password string
    password: *const c_char,
    // Input: Pointer to base64-encoded salt string
    salt: *const c_char,
    // Output: Pointer to receive the result string pointer
    out_key_b64: *mut *mut c_char,
) -> FfiError {
    // -----------------------------------------------------------------------
    // Validate input pointers
    // -----------------------------------------------------------------------
    // In FFI, null pointers are used to indicate "no value" or errors.
    // We MUST check for null before dereferencing.
    
    // If either pointer is null, we cannot proceed
    if password.is_null() || salt.is_null() {
        return FfiError::InvalidString;
    }

    // -----------------------------------------------------------------------
    // Convert C strings to Rust strings
    // -----------------------------------------------------------------------
    // CStr::from_ptr creates a borrowed reference to a C string.
    // We must use unsafe here because Rust can't verify the pointer is valid.
    // to_str() returns Result<&str, Utf8Error> if the bytes aren't valid UTF-8.
    
    // Read the password from the pointer
    let password_str = unsafe {
        match CStr::from_ptr(password).to_str() {
            Ok(s) => s,                    // Valid UTF-8, use it
            Err(_) => return FfiError::InvalidString,  // Invalid UTF-8, report error
        }
    };

    // Read the salt from the pointer (also must be valid UTF-8)
    let salt_b64 = unsafe {
        match CStr::from_ptr(salt).to_str() {
            Ok(s) => s,
            Err(_) => return FfiError::InvalidString,
        }
    };

    // -----------------------------------------------------------------------
    // Decode the base64-encoded salt
    // -----------------------------------------------------------------------
    // The salt is stored as base64 to make it easy to pass as a string.
    // We need to decode it back to raw bytes for the KDF.
    // STANDARD.decode expects base64 with standard alphabet (A-Z, a-z, 0-9, +, /)
    
    let salt_bytes = match base64::engine::general_purpose::STANDARD.decode(salt_b64) {
        Ok(b) => b,  // Decoding succeeded, use the bytes
        Err(_) => return FfiError::InvalidString,  // Invalid base64, report error
    };

    // -----------------------------------------------------------------------
    // Derive the key using Argon2id
    // -----------------------------------------------------------------------
    // Get the default Argon2id configuration (128 MiB memory, 3 iterations, 4 threads)
    let config = crate::crypto::Argon2Config::default();
    
    // Call the key derivation function from our crypto module
    match derive_key(password_str, &salt_bytes, &config) {
        Ok(master_key) => {
            // Key derivation succeeded
            // Get the raw bytes of the vault key (first 32 bytes of derived material)
            let key_bytes = master_key.vault_key.as_bytes();
            
            // Encode the key as base64 for safe transport across FFI boundary
            let key_b64 = base64::engine::general_purpose::STANDARD.encode(key_bytes);
            
            // Create a C-compatible null-terminated string from the Rust string
            // CString::new converts &str to CString, failing if the string contains interior nulls
            let c_key = CString::new(key_b64).unwrap();  // unwrap is safe here; key_b64 won't have nulls
            
            // -----------------------------------------------------------------------
            // Return the string through the output pointer
            // -----------------------------------------------------------------------
            // into_raw() consumes the CString and returns a raw pointer to the allocated memory.
            // The caller is now responsible for freeing this memory with myki_free_string.
            unsafe {
                *out_key_b64 = c_key.into_raw();
            }
            FfiError::Success
        }
        Err(_) => FfiError::DerivationFailed,  // KDF failed for some reason
    }
}

// ---------------------------------------------------------------------------
// Encryption Function (FFI)
// ---------------------------------------------------------------------------

/// Encrypts a plaintext string using a base64-encoded vault key.
/// 
/// This uses AES-256-GCM (Galois/Counter Mode), which provides both confidentiality
/// (hiding the data) and integrity (detecting tampering). The output includes a random
/// nonce and an authentication tag.
/// 
/// # Parameters
/// 
/// * `plaintext`: Pointer to the null-terminated string to encrypt. Must not be null.
/// 
/// * `key_b64`: Pointer to the null-terminated base64-encoded 256-bit vault key.
///               Must not be null. Must decode to exactly 32 bytes.
/// 
/// * `out_encrypted_b64`: Pointer to receive the base64-encoded encrypted data.
///                         Format: "base64(nonce):base64(ciphertext_with_tag)"
///                         Must be freed with `myki_free_string`.
/// 
/// # Returns
/// 
/// * `FfiError::Success` on success
/// * `FfiError::InvalidString` if inputs are null or invalid UTF-8
/// * `FfiError::InvalidKey` if key is not 32 bytes
/// * `FfiError::EncryptionFailed` if encryption itself failed
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn myki_encrypt(
    // Input: Plaintext to encrypt
    plaintext: *const c_char,
    // Input: Base64-encoded key
    key_b64: *const c_char,
    // Output: Encrypted result
    out_encrypted_b64: *mut *mut c_char,
) -> FfiError {
    // -----------------------------------------------------------------------
    // Validate input pointers
    // -----------------------------------------------------------------------
    if plaintext.is_null() || key_b64.is_null() {
        return FfiError::InvalidString;
    }

    // -----------------------------------------------------------------------
    // Read plaintext string
    // -----------------------------------------------------------------------
    let plaintext_str = unsafe {
        match CStr::from_ptr(plaintext).to_str() {
            Ok(s) => s,
            Err(_) => return FfiError::InvalidString,
        }
    };

    // -----------------------------------------------------------------------
    // Read and decode the key
    // -----------------------------------------------------------------------
    let key_b64_str = unsafe {
        match CStr::from_ptr(key_b64).to_str() {
            Ok(s) => s,
            Err(_) => return FfiError::InvalidString,
        }
    };

    // Decode base64-encoded key back to bytes
    let key_bytes = match base64::engine::general_purpose::STANDARD.decode(key_b64_str) {
        Ok(b) => b,
        Err(_) => return FfiError::InvalidKey,
    };

    // -----------------------------------------------------------------------
    // Validate key length
    // -----------------------------------------------------------------------
    // AES-256 requires a 256-bit (32 byte) key. Any other length is invalid.
    if key_bytes.len() != 32 {
        return FfiError::InvalidKey;
    }

    // -----------------------------------------------------------------------
    // Create the cipher and encrypt
    // -----------------------------------------------------------------------
    // Convert the key bytes to a VaultKey struct
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);  // copy_from_slice is safe because lengths match
    let vault_key = VaultKey::from_bytes(key_array);
    
    // Create a new AES-256-GCM cipher with this key
    let cipher = Aes256Gcm::new(&vault_key);

    // Encrypt the plaintext. The cipher generates a random nonce internally.
    // None as second parameter means no Additional Authenticated Data (AAD).
    match cipher.encrypt(plaintext_str.as_bytes(), None) {
        Ok(data) => {
            // Encryption succeeded
            // Encode the encrypted data (nonce + ciphertext) as base64
            let encoded = data.to_base64();
            let c_str = CString::new(encoded).unwrap();
            
            // Return the string to the caller
            unsafe {
                *out_encrypted_b64 = c_str.into_raw();
            }
            FfiError::Success
        }
        Err(_) => FfiError::EncryptionFailed,  // Should not happen with valid inputs
    }
}

// ---------------------------------------------------------------------------
// Decryption Function (FFI)
// ---------------------------------------------------------------------------

/// Decrypts a base64-encoded encrypted string using a base64-encoded vault key.
/// 
/// This reverses the myki_encrypt operation. The ciphertext must not be tampered with,
/// as AES-GCM includes an authentication tag that will fail verification if modified.
/// 
/// # Parameters
/// 
/// * `encrypted_b64`: Base64-encoded encrypted data from myki_encrypt. Must not be null.
/// 
/// * `key_b64`: Base64-encoded 256-bit vault key. Must not be null. Must be exactly 32 bytes.
/// 
/// * `out_plaintext`: Pointer to receive the decrypted string. Must be freed with `myki_free_string`.
/// 
/// # Returns
/// 
/// * `FfiError::Success` on successful decryption
/// * `FfiError::InvalidString` if inputs are null or invalid
/// * `FfiError::InvalidKey` if key is not 32 bytes
/// * `FfiError::DecryptionFailed` if decryption failed (wrong key, tampered data, etc.)
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn myki_decrypt(
    // Input: Encrypted data
    encrypted_b64: *const c_char,
    // Input: Base64-encoded key
    key_b64: *const c_char,
    // Output: Decrypted result
    out_plaintext: *mut *mut c_char,
) -> FfiError {
    // Validate input pointers
    if encrypted_b64.is_null() || key_b64.is_null() {
        return FfiError::InvalidString;
    }

    // Read encrypted data string
    let encrypted_str = unsafe {
        match CStr::from_ptr(encrypted_b64).to_str() {
            Ok(s) => s,
            Err(_) => return FfiError::InvalidString,
        }
    };

    // Read key string
    let key_b64_str = unsafe {
        match CStr::from_ptr(key_b64).to_str() {
            Ok(s) => s,
            Err(_) => return FfiError::InvalidString,
        }
    };

    // Decode the key from base64
    let key_bytes = match base64::engine::general_purpose::STANDARD.decode(key_b64_str) {
        Ok(b) => b,
        Err(_) => return FfiError::InvalidKey,
    };

    // Validate key length
    if key_bytes.len() != 32 {
        return FfiError::InvalidKey;
    }

    // Create VaultKey from bytes
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);
    let vault_key = VaultKey::from_bytes(key_array);
    let cipher = Aes256Gcm::new(&vault_key);

    // Parse the encrypted data from base64
    // The format is "base64(nonce):base64(ciphertext)"
    let encrypted_data = match crate::crypto::EncryptedData::from_base64(encrypted_str) {
        Ok(d) => d,
        Err(_) => return FfiError::DecryptionFailed,
    };

    // Decrypt the data
    match cipher.decrypt(&encrypted_data, None) {
        Ok(plaintext_bytes) => {
            // Decryption succeeded (authentication tag verified)
            // Convert bytes back to Rust String
            match String::from_utf8(plaintext_bytes) {
                Ok(s) => {
                    // Create C string to return to caller
                    let c_str = CString::new(s).unwrap();
                    unsafe {
                        *out_plaintext = c_str.into_raw();
                    }
                    FfiError::Success
                }
                Err(_) => FfiError::DecryptionFailed,  // Decrypted bytes weren't valid UTF-8
            }
        }
        Err(_) => FfiError::DecryptionFailed,  // Authentication tag mismatch - data was tampered
    }
}

// ---------------------------------------------------------------------------
// TOTP Generation Function (FFI)
// ---------------------------------------------------------------------------

/// Generates a current TOTP (Time-based One-Time Password) code for a given secret.
/// 
/// TOTP codes are 6-digit numbers that change every 30 seconds. They are commonly used
/// for two-factor authentication (2FA).
/// 
/// # Parameters
/// 
/// * `secret`: Pointer to a null-terminated string containing the Base32-encoded TOTP secret.
///              This is typically provided when setting up 2FA (often via QR code).
///              Must not be null.
/// 
/// * `out_code`: Pointer to receive the generated code as a null-terminated string.
///                Format: "123456" (always 6 digits)
///                Must be freed with `myki_free_string`.
/// 
/// # Returns
/// 
/// * `FfiError::Success` on successful generation
/// * `FfiError::InvalidString` if secret is null or invalid UTF-8
/// * `FfiError::DerivationFailed` if TOTP generation failed (invalid Base32 secret)
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn myki_generate_totp(
    // Input: Base32-encoded TOTP secret
    secret: *const c_char,
    // Output: Generated TOTP code
    out_code: *mut *mut c_char,
) -> FfiError {
    // Validate input
    if secret.is_null() {
        return FfiError::InvalidString;
    }

    // Read secret string
    let secret_str = unsafe {
        match CStr::from_ptr(secret).to_str() {
            Ok(s) => s,
            Err(_) => return FfiError::InvalidString,
        }
    };

    // Use default TOTP configuration: SHA1 algorithm, 6 digits, 30-second period
    // These are the most common settings and match Google Authenticator defaults
    let config = crate::totp::TotpConfig::default();
    
    // Generate the TOTP code for the current time
    match crate::totp::Totp::now(secret_str, &config) {
        Ok(code) => {
            // Success - return the code string
            let c_str = CString::new(code).unwrap();
            unsafe {
                *out_code = c_str.into_raw();
            }
            FfiError::Success
        }
        Err(_) => FfiError::DerivationFailed,  // Invalid Base32 secret
    }
}

// ---------------------------------------------------------------------------
// Base32 Validation Function (FFI)
// ---------------------------------------------------------------------------

/// Checks if a string is a valid Base32-encoded secret.
/// 
/// This is a lightweight validation function used to check if a string looks like
/// a valid TOTP secret before attempting to generate codes.
/// 
/// # Parameters
/// 
/// * `secret`: Pointer to the string to validate. Can be null.
/// 
/// # Returns
/// 
/// * `true` if the string is valid Base32 (case-insensitive, ignoring spaces and padding)
/// * `false` if null, invalid Base32, or empty
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn myki_is_valid_base32(
    // Input: String to validate
    secret: *const c_char,
) -> bool {
    // Null pointer is automatically invalid
    if secret.is_null() {
        return false;
    }

    // Read the string
    let secret_str = unsafe {
        match CStr::from_ptr(secret).to_str() {
            Ok(s) => s,
            Err(_) => return false,  // Invalid UTF-8
        }
    };

    // -----------------------------------------------------------------------
    // Normalize the string for Base32 validation
    // -----------------------------------------------------------------------
    // Base32 strings may contain:
    // - Uppercase or lowercase letters (Base32 is case-insensitive)
    // - Spaces (sometimes added for readability)
    // - Padding characters '=' (optional in some Base32 variants)
    
    let cleaned: String = secret_str
        .to_uppercase()  // Base32 is case-insensitive
        .chars()
        .filter(|c| !c.is_whitespace())  // Remove spaces
        .filter(|c| *c != '=')  // Remove padding (optional)
        .collect();

    // Attempt to decode as Base32. If it succeeds, the string is valid.
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned).is_some()
}

// ---------------------------------------------------------------------------
// Memory Deallocation Function (FFI)
// ---------------------------------------------------------------------------

/// Frees a string that was allocated by the Myki library and passed to the caller.
/// 
/// # IMPORTANT: Memory Safety
/// Every string returned via an output parameter (out_key_b64, out_encrypted_b64, etc.)
/// must eventually be passed to this function to prevent memory leaks.
/// 
/// After calling this function, the pointer is no longer valid and should not be used.
/// 
/// # Parameters
/// 
/// * `ptr`: The pointer to free. If null, this function does nothing (safe no-op).
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn myki_free_string(
    // Input: Pointer to free
    ptr: *mut c_char,
) {
    // Check if pointer is null - this is safe to skip
    if !ptr.is_null() {
        unsafe {
            // from_raw() takes a pointer and creates a CString, consuming the pointer
            // This will cause the allocated memory to be freed when the CString is dropped
            let _ = CString::from_raw(ptr);
        }
    }
    // If ptr was null, we do nothing (which is correct - null pointers weren't allocated)
}
