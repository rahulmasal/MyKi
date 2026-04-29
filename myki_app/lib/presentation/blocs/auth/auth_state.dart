import 'package:equatable/equatable.dart';

abstract class AuthState extends Equatable {
  const AuthState();

  @override
  List<Object?> get props => [];
}

class AuthInitial extends AuthState {}

class AuthLoading extends AuthState {}

class AuthNoVault extends AuthState {}

class AuthLocked extends AuthState {
  final bool biometricAvailable;

  const AuthLocked({this.biometricAvailable = false});

  @override
  List<Object?> get props => [biometricAvailable];
}

class AuthAuthenticated extends AuthState {}

class AuthError extends AuthState {
  final String message;

  const AuthError(this.message);

  @override
  List<Object?> get props => [message];
}
