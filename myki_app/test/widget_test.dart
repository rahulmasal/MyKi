import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:local_auth/local_auth.dart';
import 'package:mocktail/mocktail.dart';

import 'package:myki_app/app.dart';
import 'package:myki_app/core/services/vault_service.dart';
import 'package:myki_app/core/services/biometric_service.dart';
import 'package:myki_app/presentation/blocs/auth/auth_bloc.dart';
import 'package:myki_app/presentation/blocs/vault/vault_bloc.dart';

class MockVaultService extends Mock implements VaultService {}
class MockBiometricService extends Mock implements BiometricService {}
class MockLocalAuthentication extends Mock implements LocalAuthentication {}

void main() {
  late MockVaultService mockVaultService;
  late MockBiometricService mockBiometricService;
  late MockLocalAuthentication mockLocalAuth;

  setUp(() {
    mockVaultService = MockVaultService();
    mockBiometricService = MockBiometricService();
    mockLocalAuth = MockLocalAuthentication();

    when(() => mockLocalAuth.canCheckBiometrics).thenAnswer((_) async => false);
    when(() => mockLocalAuth.isDeviceSupported()).thenAnswer((_) async => false);
    when(() => mockVaultService.hasVault()).thenAnswer((_) async => false);
  });

  testWidgets('App loads and shows unlock page', (WidgetTester tester) async {
    await tester.pumpWidget(
      MultiBlocProvider(
        providers: [
          BlocProvider<AuthBloc>(
            create: (_) => AuthBloc(
              vaultService: mockVaultService,
              biometricService: mockBiometricService,
              localAuth: mockLocalAuth,
            ),
          ),
          BlocProvider<VaultBloc>(create: (_) => VaultBloc()),
        ],
        child: const MykiApp(),
      ),
    );

    await tester.pump();

    // Verify that the unlock page is shown (app starts locked)
    // Based on unlock_page.dart content:
    expect(find.text('Welcome Back'), findsOneWidget);
    expect(find.text('Unlock Vault'), findsOneWidget);
  });
}
