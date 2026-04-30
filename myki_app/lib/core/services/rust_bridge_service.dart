import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';

/// Error codes matching the Rust `FfiError` enum.
///
/// These values are returned by the Rust functions to indicate the result
/// of an operation, allowing the Dart side to handle errors appropriately.
enum FfiError {
  success,
  invalidString,
  derivationFailed,
  encryptionFailed,
  decryptionFailed,
  invalidKey,
}

// FFI Typedefs for Native and Dart signatures of Rust functions.
// These define the function pointer types for communication between Dart and Rust.

typedef MykiDeriveKeyNative = Int32 Function(
  Pointer<Utf8> password,
  Pointer<Utf8> salt,
  Pointer<Pointer<Utf8>> outKeyB64,
);
typedef MykiDeriveKeyDart = int Function(
  Pointer<Utf8> password,
  Pointer<Utf8> salt,
  Pointer<Pointer<Utf8>> outKeyB64,
);

typedef MykiEncryptNative = Int32 Function(
  Pointer<Utf8> plaintext,
  Pointer<Utf8> keyB64,
  Pointer<Pointer<Utf8>> outEncryptedB64,
);
typedef MykiEncryptDart = int Function(
  Pointer<Utf8> plaintext,
  Pointer<Utf8> keyB64,
  Pointer<Pointer<Utf8>> outEncryptedB64,
);

typedef MykiDecryptNative = Int32 Function(
  Pointer<Utf8> encryptedB64,
  Pointer<Utf8> keyB64,
  Pointer<Pointer<Utf8>> outPlaintext,
);
typedef MykiDecryptDart = int Function(
  Pointer<Utf8> encryptedB64,
  Pointer<Utf8> keyB64,
  Pointer<Pointer<Utf8>> outPlaintext,
);

typedef MykiGenerateTotpNative = Int32 Function(
  Pointer<Utf8> secret,
  Pointer<Pointer<Utf8>> outCode,
);
typedef MykiGenerateTotpDart = int Function(
  Pointer<Utf8> secret,
  Pointer<Pointer<Utf8>> outCode,
);

typedef MykiIsValidBase32Native = Uint8 Function(Pointer<Utf8> secret);
typedef MykiIsValidBase32Dart = int Function(Pointer<Utf8> secret);

typedef MykiFreeStringNative = Void Function(Pointer<Utf8> ptr);
typedef MykiFreeStringDart = void Function(Pointer<Utf8> ptr);

/// A service that bridges Flutter with the Rust-based security core via FFI.
///
/// This service is responsible for loading the native library and providing
/// a type-safe Dart interface for high-performance cryptographic operations
/// like key derivation, encryption, and TOTP generation.
class RustBridgeService {
  // Singleton pattern to ensure only one instance of the bridge exists.
  static final RustBridgeService _instance = RustBridgeService._internal();
  factory RustBridgeService() => _instance;
  RustBridgeService._internal();

  // The loaded dynamic library containing the Rust core.
  late DynamicLibrary _lib;
  
  // Late-initialized Dart-side function handles for the Rust functions.
  late MykiDeriveKeyDart _deriveKey;
  late MykiEncryptDart _encrypt;
  late MykiDecryptDart _decrypt;
  late MykiGenerateTotpDart _generateTotp;
  late MykiIsValidBase32Dart _isValidBase32;
  late MykiFreeStringDart _freeString;

  bool _isInitialized = false;
  /// Returns `true` if the native library has been successfully loaded and initialized.
  bool get isInitialized => _isInitialized;

  /// Initializes the service by loading the appropriate native library for the current platform.
  void initialize() {
    if (_isInitialized) return;

    // Determine the library file name based on the operating system.
    final String libName = Platform.isWindows
        ? 'myki_core.dll'
        : Platform.isMacOS
            ? 'libmyki_core.dylib'
            : 'libmyki_core.so';

    try {
      // Open the dynamic library.
      _lib = DynamicLibrary.open(libName);
      
      // Look up and bind the Rust functions to Dart variables.
      _deriveKey = _lib.lookupFunction<MykiDeriveKeyNative, MykiDeriveKeyDart>('myki_derive_key');
      _encrypt = _lib.lookupFunction<MykiEncryptNative, MykiEncryptDart>('myki_encrypt');
      _decrypt = _lib.lookupFunction<MykiDecryptNative, MykiDecryptDart>('myki_decrypt');
      _generateTotp = _lib.lookupFunction<MykiGenerateTotpNative, MykiGenerateTotpDart>('myki_generate_totp');
      _isValidBase32 = _lib.lookupFunction<MykiIsValidBase32Native, MykiIsValidBase32Dart>('myki_is_valid_base32');
      _freeString = _lib.lookupFunction<MykiFreeStringNative, MykiFreeStringDart>('myki_free_string');
      
      _isInitialized = true;
    } catch (e) {
      // If initialization fails (e.g., library not found), the service remains uninitialized.
      // debugPrint('Failed to load Rust library: $e');
    }
  }

  /// Derives a cryptographic key from a password and salt using Argon2id.
  ///
  /// [password] is the user's master password.
  /// [saltB64] is a Base64 encoded salt.
  /// Returns a Base64 encoded derived key, or `null` if the operation failed.
  String? deriveKey(String password, String saltB64) {
    if (!_isInitialized) return null;

    // Convert Dart strings to UTF-8 native memory.
    final pPassword = password.toNativeUtf8();
    final pSalt = saltB64.toNativeUtf8();
    // Allocate memory for the output pointer.
    final pOutKey = calloc<Pointer<Utf8>>();

    try {
      final result = _deriveKey(pPassword, pSalt, pOutKey);
      if (result == 0) {
        // Successfully derived key. Convert back to Dart string.
        final key = pOutKey.value.toDartString();
        // Crucial: Free the string allocated by Rust to prevent memory leaks.
        _freeString(pOutKey.value);
        return key;
      }
      return null;
    } finally {
      // Free the native memory allocated by Dart.
      calloc.free(pPassword);
      calloc.free(pSalt);
      calloc.free(pOutKey);
    }
  }

  /// Encrypts plaintext using AES-GCM with the provided key.
  ///
  /// [plaintext] is the data to encrypt.
  /// [keyB64] is the Base64 encoded encryption key.
  /// Returns Base64 encoded encrypted data (including nonce and tag), or `null`.
  String? encrypt(String plaintext, String keyB64) {
    if (!_isInitialized) return null;

    final pPlaintext = plaintext.toNativeUtf8();
    final pKey = keyB64.toNativeUtf8();
    final pOutEncrypted = calloc<Pointer<Utf8>>();

    try {
      final result = _encrypt(pPlaintext, pKey, pOutEncrypted);
      if (result == 0) {
        final encrypted = pOutEncrypted.value.toDartString();
        _freeString(pOutEncrypted.value);
        return encrypted;
      }
      return null;
    } finally {
      calloc.free(pPlaintext);
      calloc.free(pKey);
      calloc.free(pOutEncrypted);
    }
  }

  /// Decrypts ciphertext using AES-GCM with the provided key.
  ///
  /// [encryptedB64] is the Base64 encoded ciphertext.
  /// [keyB64] is the Base64 encoded decryption key.
  /// Returns the decrypted plaintext, or `null` if decryption failed.
  String? decrypt(String encryptedB64, String keyB64) {
    if (!_isInitialized) return null;

    final pEncrypted = encryptedB64.toNativeUtf8();
    final pKey = keyB64.toNativeUtf8();
    final pOutPlaintext = calloc<Pointer<Utf8>>();

    try {
      final result = _decrypt(pEncrypted, pKey, pOutPlaintext);
      if (result == 0) {
        final plaintext = pOutPlaintext.value.toDartString();
        _freeString(pOutPlaintext.value);
        return plaintext;
      }
      return null;
    } finally {
      calloc.free(pEncrypted);
      calloc.free(pKey);
      calloc.free(pOutPlaintext);
    }
  }

  /// Generates a TOTP code from a Base32 encoded secret.
  ///
  /// [secret] is the Base32 encoded secret key.
  /// Returns a 6-digit TOTP code as a string, or `null`.
  String? generateTotp(String secret) {
    if (!_isInitialized) return null;

    final pSecret = secret.toNativeUtf8();
    final pOutCode = calloc<Pointer<Utf8>>();

    try {
      final result = _generateTotp(pSecret, pOutCode);
      if (result == 0) {
        final code = pOutCode.value.toDartString();
        _freeString(pOutCode.value);
        return code;
      }
      return null;
    } finally {
      calloc.free(pSecret);
      calloc.free(pOutCode);
    }
  }

  /// Validates if a string is a valid Base32 encoded secret.
  ///
  /// Used to verify TOTP secrets before storage.
  bool isValidBase32(String secret) {
    if (!_isInitialized) return false;

    final pSecret = secret.toNativeUtf8();
    try {
      return _isValidBase32(pSecret) != 0;
    } finally {
      calloc.free(pSecret);
    }
  }
}
