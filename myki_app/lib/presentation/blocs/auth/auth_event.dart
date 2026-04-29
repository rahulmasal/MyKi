import 'package:equatable/equatable.dart';

abstract class AuthEvent extends Equatable {
  const AuthEvent();

  @override
  List<Object?> get props => [];
}

class AuthCheckStatus extends AuthEvent {}

class AuthUnlockWithPassword extends AuthEvent {
  final String password;

  const AuthUnlockWithPassword(this.password);

  @override
  List<Object?> get props => [password];
}

class AuthUnlockWithBiometric extends AuthEvent {}

class AuthLock extends AuthEvent {}

class AuthCreateVault extends AuthEvent {
  final String password;

  const AuthCreateVault(this.password);

  @override
  List<Object?> get props => [password];
}
