import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:local_auth/local_auth.dart';

import '../../../core/services/vault_service.dart';
import '../../../core/services/biometric_service.dart';
import 'auth_event.dart';
import 'auth_state.dart';

/// The Business Logic Component (BLoC) that manages the authentication lifecycle.
///
/// This BLoC coordinates between the [VaultService] for password-based security,
/// the [BiometricService] for device-level authentication, and the UI.
/// It processes [AuthEvent]s and emits [AuthState]s to drive the app's navigation
/// and security behavior.
class AuthBloc extends Bloc<AuthEvent, AuthState> {
  /// Service for handling encrypted vault operations.
  final VaultService vaultService;
  /// Service for simplifying biometric interactions.
  final BiometricService biometricService;
  /// The underlying platform plugin for biometric authentication.
  final LocalAuthentication localAuth;

  AuthBloc({
    required this.vaultService,
    required this.biometricService,
    required this.localAuth,
  }) : super(AuthInitial()) {
    // Mapping events to their respective handler functions.
    on<AuthCheckStatus>(_onCheckStatus);
    on<AuthUnlockWithPassword>(_onUnlockWithPassword);
    on<AuthUnlockWithBiometric>(_onUnlockWithBiometric);
    on<AuthLock>(_onLock);
    on<AuthCreateVault>(_onCreateVault);
  }

  /// Handles the [AuthCheckStatus] event, usually triggered on app startup.
  Future<void> _onCheckStatus(
    AuthCheckStatus event,
    Emitter<AuthState> emit,
  ) async {
    emit(AuthLoading());

    // Check if the user has already set up a vault on this device.
    final hasVault = await vaultService.hasVault();

    if (!hasVault) {
      // If no vault exists, the UI should show the onboarding/creation screen.
      emit(AuthNoVault());
      return;
    }

    // If a vault exists, determine if we can offer biometric unlock.
    final biometricAvailable = await biometricService.isAvailable();
    emit(AuthLocked(biometricAvailable: biometricAvailable));
  }

  /// Handles attempts to unlock the vault via a master password.
  Future<void> _onUnlockWithPassword(
    AuthUnlockWithPassword event,
    Emitter<AuthState> emit,
  ) async {
    emit(AuthLoading());

    try {
      // Delegate the sensitive verification logic to the VaultService.
      final success = await vaultService.unlockVault(event.password);

      if (success) {
        // Successful unlock: transit to Authenticated state.
        emit(AuthAuthenticated());
      } else {
        // Password mismatch: emit error state to show feedback in UI.
        emit(const AuthError('Invalid password'));
      }
    } catch (e) {
      emit(AuthError(e.toString()));
    }
  }

  /// Handles attempts to unlock the vault using biometrics (Fingerprint/FaceID).
  Future<void> _onUnlockWithBiometric(
    AuthUnlockWithBiometric event,
    Emitter<AuthState> emit,
  ) async {
    emit(AuthLoading());

    try {
      // Request biometric verification from the OS.
      final authenticated = await biometricService.authenticate();

      if (authenticated) {
        // In a real-world scenario, successful biometric authentication would
        // trigger the retrieval of the master key from secure storage (e.g., Keystore/Keychain).
        emit(AuthAuthenticated());
      } else {
        // Biometric failed or was cancelled; stay in the locked state.
        final biometricAvailable = await biometricService.isAvailable();
        emit(AuthLocked(biometricAvailable: biometricAvailable));
      }
    } catch (e) {
      emit(AuthError(e.toString()));
    }
  }

  /// Handles a request to manually lock the vault.
  Future<void> _onLock(AuthLock event, Emitter<AuthState> emit) async {
    // Clear the sensitive session key from memory.
    await vaultService.lockVault();
    final biometricAvailable = await biometricService.isAvailable();
    emit(AuthLocked(biometricAvailable: biometricAvailable));
  }

  /// Handles the creation of a brand new vault during onboarding.
  Future<void> _onCreateVault(
    AuthCreateVault event,
    Emitter<AuthState> emit,
  ) async {
    emit(AuthLoading());

    try {
      // Perform the multi-step vault initialization process.
      await vaultService.createVault(event.password);
      // New vault is created and auto-unlocked.
      emit(AuthAuthenticated());
    } catch (e) {
      emit(AuthError(e.toString()));
    }
  }
}
