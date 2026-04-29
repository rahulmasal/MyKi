import 'dart:convert';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'rust_bridge_service.dart';

/// Vault Service - handles encryption/decryption of vault data via Rust Core
class VaultService {
  final _storage = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock),
  );

  final _rustBridge = RustBridgeService();

  // In-memory session key (Base64 encoded, never persisted)
  String? _sessionKeyB64;

  /// Check if vault is currently unlocked and session is active
  bool get isUnlocked => _sessionKeyB64 != null;

  /// Check if vault exists
  Future<bool> hasVault() async {
    final salt = await _storage.read(key: 'vault_salt');
    return salt != null;
  }

  /// Create a new vault with master password
  Future<void> createVault(String masterPassword) async {
    _rustBridge.initialize();
    
    // Generate salt (keep in Dart for simplicity, or move to Rust later)
    final saltBytes = List<int>.generate(32, (i) => i % 256); // Placeholder, should be random
    final saltB64 = base64Encode(saltBytes);

    // Derive key using Rust Core (Argon2id)
    final derivedKeyB64 = _rustBridge.deriveKey(masterPassword, saltB64);
    if (derivedKeyB64 == null) throw Exception('Failed to derive key');

    // Store salt
    await _storage.write(key: 'vault_salt', value: saltB64);

    // Store derived key hash for verification
    final keyHash = base64Encode(utf8.encode(derivedKeyB64)); // Simple hash for demo
    await _storage.write(key: 'vault_key_hash', value: keyHash);
    
    // Auto-unlock after creation
    _sessionKeyB64 = derivedKeyB64;
  }

  /// Unlock vault with master password
  Future<bool> unlockVault(String masterPassword) async {
    _rustBridge.initialize();
    
    final saltB64 = await _storage.read(key: 'vault_salt');
    if (saltB64 == null) return false;

    // Derive key using Rust Core
    final derivedKeyB64 = _rustBridge.deriveKey(masterPassword, saltB64);
    if (derivedKeyB64 == null) return false;

    // Verify key
    final keyHash = base64Encode(utf8.encode(derivedKeyB64));
    final storedHash = await _storage.read(key: 'vault_key_hash');

    if (keyHash == storedHash) {
      _sessionKeyB64 = derivedKeyB64;
      return true;
    }
    
    return false;
  }

  /// Lock the vault and clear session key
  Future<void> lockVault() async {
    _sessionKeyB64 = null;
  }

  /// Encrypt data using Rust Core (AES-GCM)
  Future<String> encrypt(String plaintext) async {
    if (_sessionKeyB64 == null) throw Exception('Vault is locked');

    final encrypted = _rustBridge.encrypt(plaintext, _sessionKeyB64!);
    if (encrypted == null) throw Exception('Encryption failed');

    return encrypted;
  }

  /// Decrypt data using Rust Core (AES-GCM)
  Future<String> decrypt(String encryptedData) async {
    if (_sessionKeyB64 == null) throw Exception('Vault is locked');

    final decrypted = _rustBridge.decrypt(encryptedData, _sessionKeyB64!);
    if (decrypted == null) throw Exception('Decryption failed');

    return decrypted;
  }
}
