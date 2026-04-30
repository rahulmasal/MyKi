import 'package:equatable/equatable.dart';

/// Base class for all authentication states.
///
/// States are emitted by the [AuthBloc] and consumed by the UI to
/// determine which widgets to display (e.g., loading spinner, unlock page, vault).
abstract class AuthState extends Equatable {
  const AuthState();

  @override
  List<Object?> get props => [];
}

/// The initial state before any authentication status check has been performed.
class AuthInitial extends AuthState {}

/// State emitted while an asynchronous authentication operation is in progress.
class AuthLoading extends AuthState {}

/// State indicating that no vault exists on the device (first-time user).
class AuthNoVault extends AuthState {}

/// State indicating that a vault exists but is currently locked.
class AuthLocked extends AuthState {
  /// Whether biometric authentication (Fingerprint/FaceID) is available on this device.
  final bool biometricAvailable;

  const AuthLocked({this.biometricAvailable = false});

  @override
  List<Object?> get props => [biometricAvailable];
}

/// State indicating that the user has successfully authenticated and the vault is unlocked.
class AuthAuthenticated extends AuthState {}

/// State indicating that an error occurred during an authentication attempt (e.g., wrong password).
class AuthError extends AuthState {
  /// A human-readable error message.
  final String message;

  const AuthError(this.message);

  @override
  List<Object?> get props => [message];
}
