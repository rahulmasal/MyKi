import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:local_auth/local_auth.dart';
import 'package:flutter_jailbreak_detection/flutter_jailbreak_detection.dart';

import 'app.dart';
import 'core/services/vault_service.dart';
import 'core/services/biometric_service.dart';
import 'presentation/blocs/auth/auth_bloc.dart';
import 'presentation/blocs/vault/vault_bloc.dart';

/// The entry point of the Myki application.
///
/// This function initializes the Flutter framework, sets up system-level
/// configurations, and provides the necessary BLoCs to the app.
void main() async {
  // Ensures that the Flutter engine is fully initialized before any asynchronous code runs.
  WidgetsFlutterBinding.ensureInitialized();

  // Set preferred orientations to portrait mode for a consistent user experience.
  await SystemChrome.setPreferredOrientations([
    DeviceOrientation.portraitUp,
    DeviceOrientation.portraitDown,
  ]);

  // Set system UI overlay style to make the status bar transparent and use dark icons.
  SystemChrome.setSystemUIOverlayStyle(
    const SystemUiOverlayStyle(
      statusBarColor: Colors.transparent,
      statusBarIconBrightness: Brightness.dark,
    ),
  );

  // Initialize core services that will be used across the application.
  // VaultService handles secure storage and retrieval of user credentials.
  final vaultService = VaultService();
  // BiometricService manages biometric authentication workflows.
  final biometricService = BiometricService();
  // LocalAuthentication is a third-party plugin for device-level biometric checks.
  final localAuth = LocalAuthentication();

  // Check for jailbreak/root status for security hardening.
  bool isJailbroken = false;
  try {
    isJailbroken = await FlutterJailbreakDetection.jailbroken;
  } catch (e) {
    debugPrint('Failed to check jailbreak status: $e');
  }

  // Check biometric availability to inform the AuthBloc about the device's capabilities.
  final canCheckBiometrics = await localAuth.canCheckBiometrics;
  final isDeviceSupported = await localAuth.isDeviceSupported();

  // Logging biometric status for debugging purposes during initialization.
  debugPrint(
    'Biometric availability: $canCheckBiometrics, Device supported: $isDeviceSupported',
  );

  // The runApp function starts the application by mounting the root widget.
  // MultiBlocProvider is used to inject BLoCs at the top of the widget tree,
  // making them accessible to all descendant widgets.
  runApp(
    MultiBlocProvider(
      providers: [
        // AuthBloc manages the authentication state of the user (Locked vs. Unlocked).
        BlocProvider<AuthBloc>(
          create: (_) => AuthBloc(
            vaultService: vaultService,
            biometricService: biometricService,
            localAuth: localAuth,
          ),
        ),
        // VaultBloc manages the state of the credential vault, such as the list of stored credentials.
        BlocProvider<VaultBloc>(create: (_) => VaultBloc()),
      ],
      child: isJailbroken 
        ? const MaterialApp(
            debugShowCheckedModeBanner: false,
            home: Scaffold(
              body: Center(
                child: Padding(
                  padding: EdgeInsets.all(24.0),
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(Icons.warning_amber_rounded, size: 80, color: Colors.red),
                      SizedBox(height: 24),
                      Text(
                        'Security Risk Detected',
                        style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold),
                      ),
                      SizedBox(height: 16),
                      Text(
                        'Myki cannot run on jailbroken or rooted devices to protect your sensitive data. Please use a secure device.',
                        textAlign: TextAlign.center,
                        style: TextStyle(fontSize: 16),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          )
        : const MykiApp(),
    ),
  );
}
