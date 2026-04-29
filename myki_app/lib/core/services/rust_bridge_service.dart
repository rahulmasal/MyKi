import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';

/// Error codes matching Rust FfiError enum
enum FfiError {
  success,
  invalidString,
  derivationFailed,
  encryptionFailed,
  decryptionFailed,
  invalidKey,
}

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

class RustBridgeService {
  static final RustBridgeService _instance = RustBridgeService._internal();
  factory RustBridgeService() => _instance;
  RustBridgeService._internal();

  late DynamicLibrary _lib;
  late MykiDeriveKeyDart _deriveKey;
  late MykiEncryptDart _encrypt;
  late MykiDecryptDart _decrypt;
  late MykiGenerateTotpDart _generateTotp;
  late MykiIsValidBase32Dart _isValidBase32;
  late MykiFreeStringDart _freeString;

  bool _isInitialized = false;
  bool get isInitialized => _isInitialized;

  void initialize() {
    if (_isInitialized) return;

    final String libName = Platform.isWindows
        ? 'myki_core.dll'
        : Platform.isMacOS
            ? 'libmyki_core.dylib'
            : 'libmyki_core.so';

    // In a real app, you'd need to bundle this library correctly.
    // For now, we assume it's in the executable directory or system path.
    try {
      _lib = DynamicLibrary.open(libName);
      
      _deriveKey = _lib.lookupFunction<MykiDeriveKeyNative, MykiDeriveKeyDart>('myki_derive_key');
      _encrypt = _lib.lookupFunction<MykiEncryptNative, MykiEncryptDart>('myki_encrypt');
      _decrypt = _lib.lookupFunction<MykiDecryptNative, MykiDecryptDart>('myki_decrypt');
      _generateTotp = _lib.lookupFunction<MykiGenerateTotpNative, MykiGenerateTotpDart>('myki_generate_totp');
      _isValidBase32 = _lib.lookupFunction<MykiIsValidBase32Native, MykiIsValidBase32Dart>('myki_is_valid_base32');
      _freeString = _lib.lookupFunction<MykiFreeStringNative, MykiFreeStringDart>('myki_free_string');
      
      _isInitialized = true;
    } catch (e) {
      // print('Failed to load Rust library: $e');
    }
  }

  String? deriveKey(String password, String saltB64) {
    if (!_isInitialized) return null;

    final pPassword = password.toNativeUtf8();
    final pSalt = saltB64.toNativeUtf8();
    final pOutKey = calloc<Pointer<Utf8>>();

    try {
      final result = _deriveKey(pPassword, pSalt, pOutKey);
      if (result == 0) {
        final key = pOutKey.value.toDartString();
        _freeString(pOutKey.value);
        return key;
      }
      return null;
    } finally {
      calloc.free(pPassword);
      calloc.free(pSalt);
      calloc.free(pOutKey);
    }
  }

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
