//! Myki App - Flutter Application Entry Point
//!
//! This is the main entry point of the Myki password manager mobile application.
//! It initializes Flutter, sets up core services, and provides BLoC providers
//! to the entire app widget tree.

import 'package:flutter/material.dart'; // Flutter UI framework
import 'package:flutter/services.dart'; // System services (chrome, orientation)
import 'package:flutter_bloc/flutter_bloc.dart'; // BLoC state management
import 'package:local_auth/local_auth.dart'; // Biometric authentication
import 'dart:io';
import 'package:logger/logger.dart';
import 'package:path_provider/path_provider.dart';
import 'package:flutter_jailbreak_detection/flutter_jailbreak_detection.dart';

import 'app.dart'; // Root app widget
import 'core/services/vault_service.dart'; // Vault management
import 'core/services/biometric_service.dart'; // Biometric auth
import 'presentation/blocs/auth/auth_bloc.dart'; // Auth state management
import 'presentation/blocs/vault/vault_bloc.dart'; // Vault state management

// Global logger instance
late Logger appLogger;

/// Custom log output to write to file
class FileOutput extends LogOutput {
  final File file;
  FileOutput({required this.file});

  @override
  void output(OutputEvent event) {
    for (var line in event.lines) {
      file.writeAsStringSync(
        '${DateTime.now()}: $line\n',
        mode: FileMode.append,
      );
      debugPrint(line); // Also print to console
    }
  }
}

/// The entry point of the Myki application.
///
/// This async function initializes the Flutter framework and sets up
/// security services before launching the app.
///
/// # Initialization Steps
///
/// 1. **Flutter Binding**: Ensures Flutter engine is initialized
/// 2. **System UI**: Configures status bar, orientation
/// 3. **Services**: Creates VaultService, BiometricService instances
/// 4. **Security**: Checks for jailbreak/root
/// 5. **Biometrics**: Checks device biometric capabilities
/// 6. **App Launch**: Runs the app with BLoC providers
void main() async {
  // -------------------------------------------------------------------------
  // Step 1: Initialize Flutter Binding
  // -------------------------------------------------------------------------
  // WidgetsFlutterBinding.ensureInitialized() is required before using any
  // asynchronous Flutter features. It ensures the Flutter engine is fully
  // initialized before we do anything async.
  WidgetsFlutterBinding.ensureInitialized();

  // Initialize file logger
  try {
    final directory = await getApplicationDocumentsDirectory();
    final logFile = File('${directory.path}/myki_app.log');
    appLogger = Logger(
      filter: ProductionFilter(),
      printer: PrettyPrinter(colors: false, printTime: true),
      output: FileOutput(file: logFile),
    );
    appLogger.i('Application starting...');
  } catch (e) {
    debugPrint('Failed to initialize logger: $e');
    // Fallback logger if file access fails
    appLogger = Logger(printer: PrettyPrinter());
  }

  // -------------------------------------------------------------------------
  // Step 2: Configure System UI
  // -------------------------------------------------------------------------
  // Set preferred orientations to portrait mode only.
  // This provides a consistent experience and prevents layout issues
  // that could occur in landscape mode.
  await SystemChrome.setPreferredOrientations([
    DeviceOrientation.portraitUp, // Portrait, home button at bottom
    DeviceOrientation.portraitDown, // Portrait, home button at top (upsidedown)
  ]);

  // Set the status bar appearance.
  // We make it transparent with dark icons so it blends with our app design.
  SystemChrome.setSystemUIOverlayStyle(
    const SystemUiOverlayStyle(
      statusBarColor: Colors.transparent, // Transparent background
      statusBarIconBrightness:
          Brightness.dark, // Dark icons for light backgrounds
    ),
  );

  // -------------------------------------------------------------------------
  // Step 3: Initialize Core Services
  // -------------------------------------------------------------------------
  // Create instances of our security services.
  // These are passed to BLoCs which manage their lifecycle.

  // VaultService: Handles encrypted storage and key derivation.
  // It's the main interface to the vault functionality.
  final vaultService = VaultService();

  // BiometricService: Wraps the local_auth plugin for simplified
  // biometric authentication. Handles fingerprint, face unlock, etc.
  final biometricService = BiometricService();

  // LocalAuthentication: The actual plugin instance. We need this to check
  // biometric availability and capabilities.
  final localAuth = LocalAuthentication();

  // -------------------------------------------------------------------------
  // Step 4: Security Checks
  // -------------------------------------------------------------------------
  // Check if the device is jailbroken (iOS) or rooted (Android).
  // We cannot allow the app to run on compromised devices as it would
  // compromise the security of stored credentials.

  bool isJailbroken = false;
  try {
    // Attempt to detect jailbreak/root status
    isJailbroken = await FlutterJailbreakDetection.jailbroken;
  } catch (e) {
    // If the check fails for any reason, log it and assume secure.
    // This prevents false negatives if the detection plugin has issues.
    appLogger.w('Failed to check jailbreak status: $e');
  }

  // -------------------------------------------------------------------------
  // Step 5: Check Biometric Capabilities
  // -------------------------------------------------------------------------
  // Determine if this device supports biometric authentication.
  // This info is passed to the AuthBloc to show/hide biometric unlock options.

  // canCheckBiometrics: Does the device have any biometric hardware?
  final canCheckBiometrics = await localAuth.canCheckBiometrics;

  // isDeviceSupported: Does the device support local authentication?
  // (Even without biometrics, it might support PIN/pattern/password)
  final isDeviceSupported = await localAuth.isDeviceSupported();

  // Log for debugging purposes
  appLogger.i(
    'Biometric availability: $canCheckBiometrics, Device supported: $isDeviceSupported',
  );

  // -------------------------------------------------------------------------
  // Step 6: Launch the App
  // -------------------------------------------------------------------------
  // runApp() starts the Flutter application by mounting the root widget.
  // We use MultiBlocProvider to provide BLoCs to the entire widget tree.
  //
  // BlocProvider is Flutter's way of doing dependency injection for BLoCs.
  // Any widget in the tree can access these BLoCs via BlocBuilder or BlocListener.

  runApp(
    MultiBlocProvider(
      providers: [
        // AuthBloc: Manages authentication state (locked vs unlocked).
        // It handles password verification, biometric auth, and vault creation.
        BlocProvider<AuthBloc>(
          create: (_) => AuthBloc(
            vaultService: vaultService, // For password-based auth
            biometricService: biometricService, // For fingerprint/face
            localAuth: localAuth, // For checking capabilities
          ),
        ),
        // VaultBloc: Manages the credential vault state.
        // It handles loading, adding, updating, deleting credentials.
        BlocProvider<VaultBloc>(
          create: (_) => VaultBloc(vaultService: vaultService),
        ),
      ],
      child: isJailbroken
          // -------------------------------------------------------------
          // Security Warning: Device is jailbroken/rooted
          // -------------------------------------------------------------
          // If the device is compromised, we show a warning screen instead
          // of the actual app. This prevents sensitive data from being
          // accessible on insecure devices.
          ? const MaterialApp(
              debugShowCheckedModeBanner: false, // Hide debug banner
              home: Scaffold(
                body: Center(
                  child: Padding(
                    padding: EdgeInsets.all(24.0),
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        // Warning icon - large and red for emphasis
                        Icon(
                          Icons.warning_amber_rounded, // Amber warning icon
                          size: 80, // Large size
                          color: Colors.red, // Red for danger
                        ),
                        SizedBox(height: 24), // Spacing
                        // Warning title
                        Text(
                          'Security Risk Detected',
                          style: TextStyle(
                            fontSize: 24,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        SizedBox(height: 16),
                        // Detailed explanation
                        Text(
                          'Myki cannot run on jailbroken or rooted devices to protect your sensitive data. Please use a secure device.',
                          textAlign: TextAlign.center, // Center text
                          style: TextStyle(fontSize: 16),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            )
          // -------------------------------------------------------------
          // Normal App Launch
          // -------------------------------------------------------------
          : const MykiApp(), // The actual app widget (defined in app.dart)
    ),
  );
}
