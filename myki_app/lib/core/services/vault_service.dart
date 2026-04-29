import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Vault Service - handles encryption/decryption of vault data
class VaultService {
  final _storage = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock),
  );

  // Crypto instance for Argon2id
  final _argon2 = Argon2id(
    memory: 65536, // 64MB
    parallelism: 4,
    iterations: 3,
    hashLength: 64,
  );

  // AES-GCM for encryption
  final _aesGcm = AesGcm.with256bits();

  /// Check if vault exists
  Future<bool> hasVault() async {
    final salt = await _storage.read(key: 'vault_salt');
    return salt != null;
  }

  /// Create a new vault with master password
  Future<void> createVault(String masterPassword) async {
    // Generate salt
    final salt = SecretKeyData.random(length: 32);
    final saltBytes = salt.bytes;

    // Derive key using Argon2id
    final derivedKey = await _argon2.deriveKey(
      secretKey: SecretKey(utf8.encode(masterPassword)),
      nonce: saltBytes,
    );

    // Store salt (not the password)
    await _storage.write(key: 'vault_salt', value: base64Encode(saltBytes));

    // Store derived key hash for verification
    final keyBytes = await derivedKey.extractBytes();
    final keyHash = await _hashKey(keyBytes);
    await _storage.write(key: 'vault_key_hash', value: keyHash);
  }

  /// Unlock vault with master password
  Future<bool> unlockVault(String masterPassword) async {
    final saltB64 = await _storage.read(key: 'vault_salt');
    if (saltB64 == null) return false;

    final saltBytes = base64Decode(saltB64);

    // Derive key
    final derivedKey = await _argon2.deriveKey(
      secretKey: SecretKey(utf8.encode(masterPassword)),
      nonce: saltBytes,
    );

    // Verify key
    final keyBytes = await derivedKey.extractBytes();
    final keyHash = await _hashKey(keyBytes);
    final storedHash = await _storage.read(key: 'vault_key_hash');

    return keyHash == storedHash;
  }

  /// Lock the vault
  Future<void> lockVault() async {
    await _storage.delete(key: 'session_key');
  }

  /// Encrypt data
  Future<String> encrypt(String plaintext, List<int> nonce) async {
    final sessionKeyB64 = await _storage.read(key: 'session_key');
    if (sessionKeyB64 == null) throw Exception('Vault is locked');

    final keyBytes = base64Decode(sessionKeyB64);
    final key = SecretKey(keyBytes);

    final secretBox = await _aesGcm.encrypt(
      utf8.encode(plaintext),
      secretKey: key,
      nonce: nonce,
    );

    return base64Encode([
      ...secretBox.nonce,
      ...secretBox.cipherText,
      ...secretBox.mac.bytes,
    ]);
  }

  /// Decrypt data
  Future<String> decrypt(String encryptedData) async {
    final sessionKeyB64 = await _storage.read(key: 'session_key');
    if (sessionKeyB64 == null) throw Exception('Vault is locked');

    final keyBytes = base64Decode(sessionKeyB64);
    final key = SecretKey(keyBytes);

    final data = base64Decode(encryptedData);
    final nonce = data.sublist(0, 12);
    final cipherText = data.sublist(12, data.length - 16);
    final mac = data.sublist(data.length - 16);

    final secretBox = SecretBox(cipherText, nonce: nonce, mac: Mac(mac));

    final decrypted = await _aesGcm.decrypt(secretBox, secretKey: key);

    return utf8.decode(decrypted);
  }

  /// Generate random nonce
  List<int> generateNonce() {
    return SecretKeyData.random(length: 12).bytes;
  }

  /// Hash key for verification
  Future<String> _hashKey(List<int> keyBytes) async {
    final algorithm = Sha256();
    final hash = await algorithm.hash(keyBytes);
    return base64Encode(hash.bytes);
  }
}
