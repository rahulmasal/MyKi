import 'package:otp/otp.dart';
import 'rust_bridge_service.dart';

/// TOTP (Time-based One-Time Password) service implementing RFC 6238 via Rust Core
class TotpService {
  static final _rustBridge = RustBridgeService();

  /// Generate current TOTP code for a given secret
  static String generateCode(
    String secret, {
    Algorithm algorithm = Algorithm.SHA1,
    int digits = 6,
    int period = 30,
    int? timestamp,
  }) {
    _rustBridge.initialize();
    
    final cleanSecret = secret.toUpperCase().replaceAll(' ', '');
    final code = _rustBridge.generateTotp(cleanSecret);
    
    return code ?? '------';
  }

  /// Get remaining seconds until the current code expires
  static int getRemainingSeconds({int period = 30}) {
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    return period - (now % period);
  }

  /// Get progress (0.0 to 1.0) through the current period
  static double getProgress({int period = 30}) {
    final remaining = getRemainingSeconds(period: period);
    return 1.0 - (remaining / period);
  }

  /// Parse an otpauth:// URI
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

      // Override issuer from query params if present
      issuer = parsed.queryParameters['issuer'] ?? issuer;

      // Get secret (required)
      final secret = parsed.queryParameters['secret'];
      if (secret == null || secret.isEmpty) {
        return null;
      }

      // Parse optional parameters
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
      return null;
    }
  }

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

  /// Validate a base32 secret via Rust Core
  static bool isValidSecret(String secret) {
    _rustBridge.initialize();
    return _rustBridge.isValidBase32(secret);
  }

  /// Clean and normalize a secret string
  static String normalizeSecret(String secret) {
    return secret.toUpperCase().replaceAll(RegExp(r'\s+'), '');
  }
}

/// Data class for parsed TOTP URI
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

  /// Convert to Map for storage
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

  /// Create from stored Map
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

  /// Generate the current code
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
