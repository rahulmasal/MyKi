import 'package:equatable/equatable.dart';

/// Base class for all authentication-related events.
///
/// Events are dispatched from the UI to the [AuthBloc] to trigger
/// specific authentication logic or state transitions.
abstract class AuthEvent extends Equatable {
  const AuthEvent();

  @override
  List<Object?> get props => [];
}

/// Dispatched when the app starts to determine the initial authentication state.
///
/// This checks if a vault exists and if biometrics are available.
class AuthCheckStatus extends AuthEvent {}

/// Dispatched when the user attempts to unlock the vault using a master password.
class AuthUnlockWithPassword extends AuthEvent {
  /// The master password entered by the user.
  final String password;

  const AuthUnlockWithPassword(this.password);

  @override
  List<Object?> get props => [password];
}

/// Dispatched when the user attempts to unlock the vault using biometric authentication.
class AuthUnlockWithBiometric extends AuthEvent {}

/// Dispatched when the user wants to manually lock their vault.
class AuthLock extends AuthEvent {}

/// Dispatched during the onboarding process to create a brand new vault.
class AuthCreateVault extends AuthEvent {
  /// The new master password chosen by the user.
  final String password;

  const AuthCreateVault(this.password);

  @override
  List<Object?> get props => [password];
}
