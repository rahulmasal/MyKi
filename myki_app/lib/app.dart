//! Myki App - Root Application Widget
//!
//! This is the root widget of the Myki application. It configures the MaterialApp,
//! sets up theme, and uses BlocBuilder to determine which page to show based on
//! the current authentication state.
//!
//! # Security Features
//!
//! - SecureApplication: Protects the app from screenshots and screen recording
//! - BlocBuilder: Automatically rebuilds UI based on authentication state

import 'package:flutter/material.dart'; // Flutter UI framework
import 'package:flutter_bloc/flutter_bloc.dart'; // BLoC pattern support
import 'package:secure_application/secure_application.dart'; // Screenshot protection

import 'core/theme/app_theme.dart'; // App theming (colors, typography)
import 'presentation/blocs/auth/auth_bloc.dart'; // Authentication state management
import 'presentation/blocs/auth/auth_state.dart'; // Auth states
import 'presentation/pages/unlock_page.dart'; // Lock screen
import 'presentation/pages/vault_page.dart'; // Main vault screen

/// The root widget of the Myki application.
///
/// This widget sets up the [MaterialApp] and uses a [BlocBuilder] to
/// determine which page to display based on the current authentication state.
///
/// # State-Driven Navigation
///
/// The UI automatically switches between:
/// - [UnlockPage]: When user is not authenticated (locked)
/// - [VaultPage]: When user has successfully authenticated (unlocked)
///
/// # Security Layers
///
/// 1. **MaterialApp**: Provides the Flutter app structure
/// 2. **SecureApplication**: Prevents screenshots and screen recording
/// 3. **SecureGate**: Blurs content in app switcher
/// 4. **BlocBuilder**: Reacts to auth state changes
class MykiApp extends StatelessWidget {
  /// Creates a [MykiApp] widget.
  ///
  /// This is a stateless widget because all state is managed externally
  /// via BLoC. The widget just rebuilds based on state changes.
  const MykiApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      // App title shown in task switcher
      title: 'Myki: P2P Vault',

      // Hide the debug banner in release builds
      debugShowCheckedModeBanner: false,

      // Apply the app's visual theme
      theme: AppTheme.lightTheme,

      // Use system theme preference (light/dark mode)
      themeMode: ThemeMode.system,

      // The builder function is called for every page navigation.
      // We wrap the app with security features here.
      builder: (context, child) {
        return SecureApplication(
          // -----------------------------------------------------------------
          // Authentication Callback
          // -----------------------------------------------------------------
          // This is called when the system needs to unlock the app
          // (e.g., when returning from app switcher).
          //
          // For now, we auto-unlock because the primary auth is handled
          // by AuthBloc. This mainly provides screen security in the
          // task switcher (SecureGate handles the blur).
          onNeedUnlock: (controller) async {
            // Resume the session by unlocking
            controller?.unlock();

            // Return success status - we've handled the unlock
            return SecureApplicationAuthenticationStatus.SUCCESS;
          },

          // -----------------------------------------------------------------
          // Security Gate
          // -----------------------------------------------------------------
          // SecureGate blurs and dims the app content when:
          // - App goes to background (app switcher)
          // - System takes screenshot (if secure_application detects it)
          //
          // This prevents sensitive data from being visible in the
          // task switcher or in screenshots.
          child: SecureGate(
            blurr: 20, // Blur intensity (0-25 typically)
            opacity: 0.6, // Dimming effect (0.0 to 1.0)
            child: child!, // The actual page content
          ),
        );
      },

      // -----------------------------------------------------------------
      // Home Page: Determined by Auth State
      // -----------------------------------------------------------------
      // BlocBuilder listens to AuthBloc and rebuilds whenever the state changes.
      // This is how we navigate between lock screen and vault automatically.
      home: BlocBuilder<AuthBloc, AuthState>(
        // BlocBuilder calls the builder function whenever the AuthState changes
        builder: (context, state) {
          // Check the current authentication state

          // AuthAuthenticated: User has unlocked the vault
          // Show the main vault page with credentials
          if (state is AuthAuthenticated) {
            return const VaultPage();
          }

          // All other states: Initial, Authenticating, NoVault, Locked, Error
          // Keep the user on the unlock page to authenticate
          return const UnlockPage();
        },
      ),
    );
  }
}
