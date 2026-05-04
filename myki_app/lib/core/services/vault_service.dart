import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:crypto/crypto.dart';
import 'rust_bridge_service.dart';

/// Vault Service - manages the security lifecycle of the user's credential vault.
///
/// This service handles the creation, unlocking, and management of the encrypted
/// vault. It utilizes the [RustBridgeService] for high-performance, industry-standard
/// cryptographic operations (Argon2id for KDF, AES-GCM for encryption).
///
/// Sensitive data like the derived session key is kept strictly in-memory and
/// is never persisted to disk.
class VaultService {
  // Secure persistent storage for non-volatile security metadata (e.g., salt, key hash).
  // Uses EncryptedSharedPreferences on Android and Keychain on iOS.
  final _storage = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock),
  );

  // Access to the Rust-based security core.
  final _rustBridge = RustBridgeService();

  // In-memory session key (Base64 encoded).
  // This key is derived from the master password and used for all encryption/decryption
  // operations while the vault is unlocked. It is cleared when the vault is locked.
  String? _sessionKeyB64;

  /// Returns `true` if the vault is currently unlocked and the session key is available.
  bool get isUnlocked => _sessionKeyB64 != null;

  /// Checks if a vault already exists on this device.
  ///
  /// This is determined by the presence of a stored vault salt.
  Future<bool> hasVault() async {
    final salt = await _storage.read(key: 'vault_salt');
    return salt != null;
  }

  /// Checks if the master password meets minimum strength requirements.
  bool _isPasswordStrong(String password) {
    if (password.length < 12) return false;
    if (!password.contains(RegExp(r'[A-Z]'))) return false;
    if (!password.contains(RegExp(r'[a-z]'))) return false;
    if (!password.contains(RegExp(r'[0-9]'))) return false;
    if (!password.contains(RegExp(r'[!@#\$%^&*(),.?":{}|<>]'))) return false;
    return true;
  }

  /// Creates a new vault protected by the provided [masterPassword].
  ///
  /// This involves:
  /// 1. Generating a random salt.
  /// 2. Deriving a strong master key using Argon2id via the Rust core.
  /// 3. Storing a hash of the derived key for future verification.
  /// 4. Auto-unlocking the vault by setting the session key.
  Future<void> createVault(String masterPassword) async {
    if (!_isPasswordStrong(masterPassword)) {
      throw Exception('Password does not meet strength requirements');
    }

    _rustBridge.initialize();

    // Generate a cryptographically secure random salt using the Rust core.
    final saltBytes = _rustBridge.generateSalt();
    if (saltBytes == null) throw Exception('Failed to generate salt');
    final saltB64 = base64Encode(saltBytes);

    // Derive the master key using the strong Argon2id KDF in the Rust core.
    final derivedKeyB64 = _rustBridge.deriveKey(masterPassword, saltB64);
    if (derivedKeyB64 == null) throw Exception('Failed to derive key');

    // Persist the salt needed for future key derivations.
    await _storage.write(key: 'vault_salt', value: saltB64);

    // Derive a separate hash for verification using Argon2id to avoid fast-hash vulnerabilities
    final verificationSaltBytes = _rustBridge.generateSalt();
    if (verificationSaltBytes == null) throw Exception('Failed to generate verification salt');
    final verificationSaltB64 = base64Encode(verificationSaltBytes);

    final keyHash = _rustBridge.deriveKey(derivedKeyB64, verificationSaltB64);
    if (keyHash == null) throw Exception('Failed to derive verification hash');

    await _storage.write(key: 'vault_verification_salt', value: verificationSaltB64);
    await _storage.write(key: 'vault_key_hash', value: keyHash);

    // Set the session key to unlock the vault.
    _sessionKeyB64 = derivedKeyB64;
  }

  /// Attempts to unlock the vault with the provided [masterPassword].
  ///
  /// Returns `true` if the password is correct and the vault was successfully unlocked.
  Future<bool> unlockVault(String masterPassword) async {
    _rustBridge.initialize();

    // Retrieve the salt associated with this vault.
    final saltB64 = await _storage.read(key: 'vault_salt');
    if (saltB64 == null) return false;

    // Derive the key using the same KDF parameters used during vault creation.
    final derivedKeyB64 = _rustBridge.deriveKey(masterPassword, saltB64);
    if (derivedKeyB64 == null) return false;

    // Verify the derived key against the stored hash.
    final verificationSaltB64 = await _storage.read(key: 'vault_verification_salt');
    String keyHash;

    if (verificationSaltB64 != null) {
      // Use the new Argon2id based verification
      keyHash = _rustBridge.deriveKey(derivedKeyB64, verificationSaltB64) ?? '';
    } else {
      // Fallback for older vaults using SHA-256
      keyHash = sha256.convert(utf8.encode(derivedKeyB64)).toString();
    }

    final storedHash = await _storage.read(key: 'vault_key_hash');

    if (keyHash == storedHash) {
      // If the hashes match, the password is correct. Store the session key.
      _sessionKeyB64 = derivedKeyB64;
      return true;
    }

    return false;
  }

  /// Locks the vault and wipes the session key from memory.
  Future<void> lockVault() async {
    _sessionKeyB64 = null;
  }

  /// Encrypts [plaintext] using the current session key.
  ///
  /// Uses AES-GCM (Authenticated Encryption) provided by the Rust core.
  /// Throws an exception if the vault is locked.
  Future<String> encrypt(String plaintext) async {
    if (_sessionKeyB64 == null) throw Exception('Vault is locked');

    final encrypted = _rustBridge.encrypt(plaintext, _sessionKeyB64!);
    if (encrypted == null) throw Exception('Encryption failed');

    return encrypted;
  }

  /// Decrypts [encryptedData] using the current session key.
  ///
  /// Throws an exception if the vault is locked or if decryption fails (e.g., bad tag).
  Future<String> decrypt(String encryptedData) async {
    if (_sessionKeyB64 == null) throw Exception('Vault is locked');

    final decrypted = _rustBridge.decrypt(encryptedData, _sessionKeyB64!);
    if (decrypted == null) throw Exception('Decryption failed');

    return decrypted;
  }
}
