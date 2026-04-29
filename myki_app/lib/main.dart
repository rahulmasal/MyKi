import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:local_auth/local_auth.dart';

import 'app.dart';
import 'core/services/vault_service.dart';
import 'core/services/biometric_service.dart';
import 'presentation/blocs/auth/auth_bloc.dart';
import 'presentation/blocs/vault/vault_bloc.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Set preferred orientations
  await SystemChrome.setPreferredOrientations([
    DeviceOrientation.portraitUp,
    DeviceOrientation.portraitDown,
  ]);

  // Set system UI overlay style
  SystemChrome.setSystemUIOverlayStyle(
    const SystemUiOverlayStyle(
      statusBarColor: Colors.transparent,
      statusBarIconBrightness: Brightness.dark,
    ),
  );

  // Initialize services
  final vaultService = VaultService();
  final biometricService = BiometricService();
  final localAuth = LocalAuthentication();

  // Check biometric availability (passed to AuthBloc for initial state)
  final canCheckBiometrics = await localAuth.canCheckBiometrics;
  final isDeviceSupported = await localAuth.isDeviceSupported();

  // Store for potential future use
  debugPrint(
    'Biometric availability: $canCheckBiometrics, Device supported: $isDeviceSupported',
  );

  runApp(
    MultiBlocProvider(
      providers: [
        BlocProvider<AuthBloc>(
          create: (_) => AuthBloc(
            vaultService: vaultService,
            biometricService: biometricService,
            localAuth: localAuth,
          ),
        ),
        BlocProvider<VaultBloc>(create: (_) => VaultBloc()),
      ],
      child: const MykiApp(),
    ),
  );
}
