use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use crate::crypto::{derive_key, Aes256Gcm, VaultKey};
use base64::Engine as _;

/// Error codes returned by FFI functions to indicate success or specific failure types.
#[repr(C)]
pub enum FfiError {
    /// Operation completed successfully.
    Success = 0,
    /// Provided string was null or contained invalid UTF-8.
    InvalidString = 1,
    /// Failed to derive a key from the password and salt.
    DerivationFailed = 2,
    /// Encryption operation failed.
    EncryptionFailed = 3,
    /// Decryption operation failed.
    DecryptionFailed = 4,
    /// The provided key was invalid (e.g., wrong length).
    InvalidKey = 5,
}

/// Derives a 256-bit vault key from a password and a base64-encoded salt.
/// 
/// This uses the Argon2id algorithm, which is designed to be resistant to GPU-based
/// cracking attacks by requiring a significant amount of memory and CPU time.
/// 
/// # Parameters
/// - `password`: The user's master password.
/// - `salt`: A base64-encoded random salt to prevent rainbow table attacks.
/// - `out_key_b64`: Pointer to a string that will receive the base64-encoded derived key.
///                  The caller is responsible for freeing this memory using `myki_free_string`.
/// 
/// # Returns
/// - `FfiError::Success` if successful, otherwise an error code.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn myki_derive_key(
    password: *const c_char,
    salt: *const c_char,
    out_key_b64: *mut *mut c_char,
) -> FfiError {
    if password.is_null() || salt.is_null() {
        return FfiError::InvalidString;
    }

    let password_str = unsafe {
        match CStr::from_ptr(password).to_str() {
            Ok(s) => s,
            Err(_) => return FfiError::InvalidString,
        }
    };

    let salt_b64 = unsafe {
        match CStr::from_ptr(salt).to_str() {
            Ok(s) => s,
            Err(_) => return FfiError::InvalidString,
        }
    };

    let salt_bytes = match base64::engine::general_purpose::STANDARD.decode(salt_b64) {
        Ok(b) => b,
        Err(_) => return FfiError::InvalidString,
    };

    // Use default config for now
    let config = crate::crypto::Argon2Config::default();
    
    match derive_key(password_str, &salt_bytes, &config) {
        Ok(master_key) => {
            let key_bytes = master_key.vault_key.as_bytes();
            let key_b64 = base64::engine::general_purpose::STANDARD.encode(key_bytes);
            let c_key = CString::new(key_b64).unwrap();
            unsafe {
                *out_key_b64 = c_key.into_raw();
            }
            FfiError::Success
        }
        Err(_) => FfiError::DerivationFailed,
    }
}

/// Encrypts a plaintext string using a base64-encoded vault key.
/// 
/// This uses AES-256-GCM, which provides both confidentiality and integrity.
/// The output includes a random nonce and an authentication tag.
/// 
/// # Parameters
/// - `plaintext`: The string to encrypt.
/// - `key_b64`: The base64-encoded 256-bit vault key.
/// - `out_encrypted_b64`: Pointer to a string that will receive the base64-encoded encrypted data
///                        in the format "nonce:ciphertext".
///                        The caller is responsible for freeing this memory using `myki_free_string`.
/// 
/// # Returns
/// - `FfiError::Success` if successful, otherwise an error code.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn myki_encrypt(
    plaintext: *const c_char,
    key_b64: *const c_char,
    out_encrypted_b64: *mut *mut c_char,
) -> FfiError {
    if plaintext.is_null() || key_b64.is_null() {
        return FfiError::InvalidString;
    }

    let plaintext_str = unsafe {
        match CStr::from_ptr(plaintext).to_str() {
            Ok(s) => s,
            Err(_) => return FfiError::InvalidString,
        }
    };

    let key_b64_str = unsafe {
        match CStr::from_ptr(key_b64).to_str() {
            Ok(s) => s,
            Err(_) => return FfiError::InvalidString,
        }
    };

    let key_bytes = match base64::engine::general_purpose::STANDARD.decode(key_b64_str) {
        Ok(b) => b,
        Err(_) => return FfiError::InvalidKey,
    };

    if key_bytes.len() != 32 {
        return FfiError::InvalidKey;
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);
    let vault_key = VaultKey::from_bytes(key_array);
    let cipher = Aes256Gcm::new(&vault_key);

    match cipher.encrypt(plaintext_str.as_bytes(), None) {
        Ok(data) => {
            let encoded = data.to_base64();
            let c_str = CString::new(encoded).unwrap();
            unsafe {
                *out_encrypted_b64 = c_str.into_raw();
            }
            FfiError::Success
        }
        Err(_) => FfiError::EncryptionFailed,
    }
}

/// Decrypts a base64-encoded encrypted string using a base64-encoded vault key.
/// 
/// # Parameters
/// - `encrypted_b64`: The base64-encoded encrypted data in "nonce:ciphertext" format.
/// - `key_b64`: The base64-encoded 256-bit vault key.
/// - `out_plaintext`: Pointer to a string that will receive the decrypted plaintext.
///                    The caller is responsible for freeing this memory using `myki_free_string`.
/// 
/// # Returns
/// - `FfiError::Success` if successful, otherwise an error code.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn myki_decrypt(
    encrypted_b64: *const c_char,
    key_b64: *const c_char,
    out_plaintext: *mut *mut c_char,
) -> FfiError {
    if encrypted_b64.is_null() || key_b64.is_null() {
        return FfiError::InvalidString;
    }

    let encrypted_str = unsafe {
        match CStr::from_ptr(encrypted_b64).to_str() {
            Ok(s) => s,
            Err(_) => return FfiError::InvalidString,
        }
    };

    let key_b64_str = unsafe {
        match CStr::from_ptr(key_b64).to_str() {
            Ok(s) => s,
            Err(_) => return FfiError::InvalidString,
        }
    };

    let key_bytes = match base64::engine::general_purpose::STANDARD.decode(key_b64_str) {
        Ok(b) => b,
        Err(_) => return FfiError::InvalidKey,
    };

    if key_bytes.len() != 32 {
        return FfiError::InvalidKey;
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);
    let vault_key = VaultKey::from_bytes(key_array);
    let cipher = Aes256Gcm::new(&vault_key);

    let encrypted_data = match crate::crypto::EncryptedData::from_base64(encrypted_str) {
        Ok(d) => d,
        Err(_) => return FfiError::DecryptionFailed,
    };

    match cipher.decrypt(&encrypted_data, None) {
        Ok(plaintext_bytes) => {
            match String::from_utf8(plaintext_bytes) {
                Ok(s) => {
                    let c_str = CString::new(s).unwrap();
                    unsafe {
                        *out_plaintext = c_str.into_raw();
                    }
                    FfiError::Success
                }
                Err(_) => FfiError::DecryptionFailed,
            }
        }
        Err(_) => FfiError::DecryptionFailed,
    }
}

/// Generates a current TOTP (Time-based One-Time Password) code for a given secret.
/// 
/// # Parameters
/// - `secret`: The Base32-encoded TOTP secret.
/// - `out_code`: Pointer to a string that will receive the 6-digit TOTP code.
///               The caller is responsible for freeing this memory using `myki_free_string`.
/// 
/// # Returns
/// - `FfiError::Success` if successful, otherwise an error code.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn myki_generate_totp(
    secret: *const c_char,
    out_code: *mut *mut c_char,
) -> FfiError {
    if secret.is_null() {
        return FfiError::InvalidString;
    }

    let secret_str = unsafe {
        match CStr::from_ptr(secret).to_str() {
            Ok(s) => s,
            Err(_) => return FfiError::InvalidString,
        }
    };

    let config = crate::totp::TotpConfig::default();
    
    match crate::totp::Totp::now(secret_str, &config) {
        Ok(code) => {
            let c_str = CString::new(code).unwrap();
            unsafe {
                *out_code = c_str.into_raw();
            }
            FfiError::Success
        }
        Err(_) => FfiError::DerivationFailed,
    }
}

/// Checks if a string is a valid Base32-encoded secret.
/// 
/// This is used to validate TOTP secrets before attempting to generate codes.
/// 
/// # Parameters
/// - `secret`: The string to validate.
/// 
/// # Returns
/// - `true` if valid, `false` otherwise.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn myki_is_valid_base32(secret: *const c_char) -> bool {
    if secret.is_null() {
        return false;
    }

    let secret_str = unsafe {
        match CStr::from_ptr(secret).to_str() {
            Ok(s) => s,
            Err(_) => return false,
        }
    };

    let cleaned: String = secret_str
        .to_uppercase()
        .chars()
        .filter(|c| !c.is_whitespace())
        .filter(|c| *c != '=')
        .collect();

    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned).is_some()
}

/// Frees a string that was allocated by the Myki library and passed to the caller.
/// 
/// Every string returned via a `*mut *mut c_char` parameter must eventually be
/// passed to this function to prevent memory leaks.
/// 
/// # Parameters
/// - `ptr`: The pointer to the string to free.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn myki_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}
