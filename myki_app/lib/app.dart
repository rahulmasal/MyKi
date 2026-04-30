import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';

import 'core/theme/app_theme.dart';
import 'presentation/blocs/auth/auth_bloc.dart';
import 'presentation/blocs/auth/auth_state.dart';
import 'presentation/pages/unlock_page.dart';
import 'presentation/pages/vault_page.dart';

/// The root widget of the Myki application.
///
/// This widget sets up the [MaterialApp] and uses a [BlocBuilder] to
/// determine which page to display based on the current authentication state.
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
