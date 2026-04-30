import 'package:local_auth/local_auth.dart';

/// Biometric Service - handles biometric authentication.
///
/// This service acts as a wrapper around the `local_auth` plugin,
/// providing a simplified interface for checking biometric availability
/// and performing authentication. It is a key part of the local security
/// model, allowing users to unlock their vault without typing a master password.
class BiometricService {
  // Instance of the local_auth plugin used for low-level biometric interactions.
  final LocalAuthentication _localAuth = LocalAuthentication();

  /// Checks if biometrics are available and supported on the current device.
  ///
  /// Returns `true` if the device can check biometrics and supports at least
  /// one biometric method (e.g., Fingerprint, FaceID).
  Future<bool> isAvailable() async {
    final canCheckBiometrics = await _localAuth.canCheckBiometrics;
    final isDeviceSupported = await _localAuth.isDeviceSupported();
    return canCheckBiometrics && isDeviceSupported;
  }

  /// Retrieves the list of available biometric types on the device.
  ///
  /// This can include [BiometricType.fingerprint], [BiometricType.face], etc.
  Future<List<BiometricType>> getAvailableBiometrics() async {
    return await _localAuth.getAvailableBiometrics();
  }

  /// Authenticates the user using biometrics.
  ///
  /// [reason] is the message displayed to the user explaining why they need to authenticate.
  /// Returns `true` if authentication was successful, `false` otherwise.
  Future<bool> authenticate({
    String reason = 'Authenticate to unlock your vault',
  }) async {
    try {
      // Calls the platform-specific biometric dialog.
      return await _localAuth.authenticate(
        localizedReason: reason,
        options: const AuthenticationOptions(
          // stickyAuth: true keeps the authentication active if the app goes to background.
          stickyAuth: true,
          // biometricOnly: false allows falling back to device PIN/Pattern/Password.
          biometricOnly: false,
        ),
      );
    } catch (e) {
      // In case of an error (e.g., user cancels, hardware failure), return false.
      return false;
    }
  }
}
