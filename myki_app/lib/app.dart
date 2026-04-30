import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:secure_application/secure_application.dart';

import 'core/theme/app_theme.dart';
import 'presentation/blocs/auth/auth_bloc.dart';
import 'presentation/blocs/auth/auth_state.dart';
import 'presentation/pages/unlock_page.dart';
import 'presentation/pages/vault_page.dart';

/// The root widget of the Myki application.
///
/// This widget sets up the [MaterialApp] and uses a [BlocBuilder] to
/// determine which page to display based on the current authentication state.
/// It also uses [SecureApplication] to protect sensitive data from being
/// screenshotted or visible in the task switcher.
class MykiApp extends StatelessWidget {
  /// Creates a [MykiApp] widget.
  const MykiApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Myki: P2P Vault',
      debugShowCheckedModeBanner: false,
      // Sets the visual theme for the entire application.
      theme: AppTheme.lightTheme,
      // Uses the system setting to determine whether to use dark or light theme.
      themeMode: ThemeMode.system,
      builder: (context, child) {
        return SecureApplication(
          // Auto-unlock for now as primary auth is handled by AuthBloc.
          // This mainly provides screen security in the task switcher.
          onNeedUnlock: (controller) async {
            controller?.unlock();
            return SecureApplicationAuthenticationStatus.SUCCESS;
          },
          child: SecureGate(
            blurr: 20,
            opacity: 0.6,
            child: child!,
          ),
        );
      },
      // The home property uses BlocBuilder to listen for changes in AuthBloc.
      home: BlocBuilder<AuthBloc, AuthState>(
        builder: (context, state) {
          // If the state is AuthAuthenticated, the user has successfully
          // unlocked the app, and we show the main VaultPage.
          if (state is AuthAuthenticated) {
            return const VaultPage();
          }
          // For all other states (Initial, Authenticating, Failure), we
          // keep the user on the UnlockPage to prompt for credentials.
          return const UnlockPage();
        },
      ),
    );
  }
}
