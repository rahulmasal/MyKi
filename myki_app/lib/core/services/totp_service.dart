import 'package:otp/otp.dart';
import 'rust_bridge_service.dart';

/// TOTP (Time-based One-Time Password) service.
///
/// This service implements RFC 6238 for generating one-time passwords.
/// It delegates the core cryptographic generation and validation to the
/// Rust core via [RustBridgeService] for enhanced security and performance.
class TotpService {
  // Access to the Rust-based security core.
  static final _rustBridge = RustBridgeService();

  // Track initialization state to avoid repeated initialization calls
  static bool _initialized = false;

  /// Generates the current 6-digit TOTP code for a given secret.
  ///
  /// [secret] must be a valid Base32 encoded string.
  /// The generation logic (HMAC-SHA1) is performed within the Rust core.
  static String generateCode(
    String secret, {
    Algorithm algorithm = Algorithm.SHA1,
    int digits = 6,
    int period = 30,
    int? timestamp,
  }) {
    // Ensure the native library is loaded before use (only once).
    if (!_initialized) {
      _rustBridge.initialize();
      _initialized = true;
    }

    // Normalize the secret (remove spaces, ensure uppercase).
    final cleanSecret = secret.toUpperCase().replaceAll(' ', '');
    // Call the Rust core to generate the code.
    final code = _rustBridge.generateTotp(cleanSecret);

    // Return the code or a placeholder if generation fails.
    return code ?? '------';
  }

  /// Calculates the remaining seconds in the current TOTP time step.
  ///
  /// Typically, TOTP codes change every 30 seconds.
  static int getRemainingSeconds({int period = 30}) {
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    return period - (now % period);
  }

  /// Returns the progress (0.0 to 1.0) through the current time step.
  ///
  /// This is useful for animating progress bars or countdown timers in the UI.
  static double getProgress({int period = 30}) {
    final remaining = getRemainingSeconds(period: period);
    return 1.0 - (remaining / period);
  }

  /// Parses an `otpauth://` URI into a [TotpUriData] object.
  ///
  /// These URIs are standard for sharing TOTP secrets via QR codes.
  /// Example: `otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example`
  static TotpUriData? parseOtpAuthUri(String uri) {
    try {
      final parsed = Uri.parse(uri);

      if (parsed.scheme != 'otpauth') {
        return null;
      }

      if (parsed.host != 'totp') {
        return null;
      }

      final path = Uri.decodeComponent(parsed.path);
      String label = path.startsWith('/') ? path.substring(1) : path;

      // Parse issuer and account from label (format: "Issuer:account" or just "account")
      String? issuer;
      String account;

      if (label.contains(':')) {
        final parts = label.split(':');
        issuer = parts[0];
        account = parts.sublist(1).join(':');
      } else {
        account = label;
      }

      // Override issuer from query params if present (standard practice).
      issuer = parsed.queryParameters['issuer'] ?? issuer;

      // Get secret (required for a valid TOTP entry).
      final secret = parsed.queryParameters['secret'];
      if (secret == null || secret.isEmpty) {
        return null;
      }

      // Parse optional parameters, defaulting to standard TOTP values if missing.
      final algorithm = _parseAlgorithm(parsed.queryParameters['algorithm']);
      final digits = int.tryParse(parsed.queryParameters['digits'] ?? '6') ?? 6;
      final period =
          int.tryParse(parsed.queryParameters['period'] ?? '30') ?? 30;

      return TotpUriData(
        type: 'totp',
        label: label,
        issuer: issuer,
        account: account,
        secret: secret.toUpperCase().replaceAll(' ', ''),
        algorithm: algorithm,
        digits: digits,
        period: period,
      );
    } catch (e) {
      // Return null if the URI is malformed or missing required data.
      return null;
    }
  }

  /// Helper to map string algorithm names to the [Algorithm] enum.
  static Algorithm _parseAlgorithm(String? algo) {
    switch (algo?.toUpperCase()) {
      case 'SHA256':
        return Algorithm.SHA256;
      case 'SHA512':
        return Algorithm.SHA512;
      default:
        return Algorithm.SHA1;
    }
  }

  /// Validates if a string is a valid Base32 encoded secret using the Rust core.
  static bool isValidSecret(String secret) {
    _rustBridge.initialize();
    return _rustBridge.isValidBase32(secret);
  }

  /// Normalizes a secret string for storage and generation.
  static String normalizeSecret(String secret) {
    return secret.toUpperCase().replaceAll(RegExp(r'\s+'), '');
  }
}

/// A data class that holds the parameters for a TOTP account.
class TotpUriData {
  final String type;
  final String label;
  final String? issuer;
  final String account;
  final String secret;
  final Algorithm algorithm;
  final int digits;
  final int period;

  TotpUriData({
    required this.type,
    required this.label,
    this.issuer,
    required this.account,
    required this.secret,
    required this.algorithm,
    required this.digits,
    required this.period,
  });

  /// Serializes the TOTP data to a map for JSON storage.
  Map<String, dynamic> toMap() {
    return {
      'type': type,
      'label': label,
      'issuer': issuer,
      'account': account,
      'secret': secret,
      'algorithm': algorithm.name.toUpperCase(),
      'digits': digits,
      'period': period,
    };
  }

  /// Deserializes the TOTP data from a stored map.
  factory TotpUriData.fromMap(Map<String, dynamic> map) {
    Algorithm algo;
    switch (map['algorithm']?.toString().toUpperCase()) {
      case 'SHA256':
        algo = Algorithm.SHA256;
        break;
      case 'SHA512':
        algo = Algorithm.SHA512;
        break;
      default:
        algo = Algorithm.SHA1;
    }

    return TotpUriData(
      type: map['type'] ?? 'totp',
      label: map['label'] ?? '',
      issuer: map['issuer'],
      account: map['account'] ?? '',
      secret: map['secret'] ?? '',
      algorithm: algo,
      digits: map['digits'] ?? 6,
      period: map['period'] ?? 30,
    );
  }

  /// Generates the current TOTP code for this account.
  String generateCode({int? timestamp}) {
    return TotpService.generateCode(
      secret,
      algorithm: algorithm,
      digits: digits,
      period: period,
      timestamp: timestamp,
    );
  }
}
