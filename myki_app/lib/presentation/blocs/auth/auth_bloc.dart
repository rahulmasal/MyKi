import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:local_auth/local_auth.dart';

import '../../../core/services/vault_service.dart';
import '../../../core/services/biometric_service.dart';
import 'auth_event.dart';
import 'auth_state.dart';

class AuthBloc extends Bloc<AuthEvent, AuthState> {
  final VaultService vaultService;
  final BiometricService biometricService;
  final LocalAuthentication localAuth;

  AuthBloc({
    required this.vaultService,
    required this.biometricService,
    required this.localAuth,
  }) : super(AuthInitial()) {
    on<AuthCheckStatus>(_onCheckStatus);
    on<AuthUnlockWithPassword>(_onUnlockWithPassword);
    on<AuthUnlockWithBiometric>(_onUnlockWithBiometric);
    on<AuthLock>(_onLock);
    on<AuthCreateVault>(_onCreateVault);
  }

  Future<void> _onCheckStatus(
    AuthCheckStatus event,
    Emitter<AuthState> emit,
  ) async {
    emit(AuthLoading());

    final hasVault = await vaultService.hasVault();

    if (!hasVault) {
      emit(AuthNoVault());
      return;
    }

    final biometricAvailable = await biometricService.isAvailable();
    emit(AuthLocked(biometricAvailable: biometricAvailable));
  }

  Future<void> _onUnlockWithPassword(
    AuthUnlockWithPassword event,
    Emitter<AuthState> emit,
  ) async {
    emit(AuthLoading());

    try {
      final success = await vaultService.unlockVault(event.password);

      if (success) {
        emit(AuthAuthenticated());
      } else {
        emit(const AuthError('Invalid password'));
      }
    } catch (e) {
      emit(AuthError(e.toString()));
    }
  }

  Future<void> _onUnlockWithBiometric(
    AuthUnlockWithBiometric event,
    Emitter<AuthState> emit,
  ) async {
    emit(AuthLoading());

    try {
      final authenticated = await biometricService.authenticate();

      if (authenticated) {
        // In a real app, we'd retrieve the stored session key
        // For now, we just emit authenticated state
        emit(AuthAuthenticated());
      } else {
        final biometricAvailable = await biometricService.isAvailable();
        emit(AuthLocked(biometricAvailable: biometricAvailable));
      }
    } catch (e) {
      emit(AuthError(e.toString()));
    }
  }

  Future<void> _onLock(AuthLock event, Emitter<AuthState> emit) async {
    await vaultService.lockVault();
    final biometricAvailable = await biometricService.isAvailable();
    emit(AuthLocked(biometricAvailable: biometricAvailable));
  }

  Future<void> _onCreateVault(
    AuthCreateVault event,
    Emitter<AuthState> emit,
  ) async {
    emit(AuthLoading());

    try {
      await vaultService.createVault(event.password);
      emit(AuthAuthenticated());
    } catch (e) {
      emit(AuthError(e.toString()));
    }
  }
}
