import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';

import 'core/theme/app_theme.dart';
import 'presentation/blocs/auth/auth_bloc.dart';
import 'presentation/blocs/auth/auth_state.dart';
import 'presentation/pages/unlock_page.dart';
import 'presentation/pages/vault_page.dart';

class MykiApp extends StatelessWidget {
  const MykiApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Myki',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.lightTheme,
      themeMode: ThemeMode.system,
      home: BlocBuilder<AuthBloc, AuthState>(
        builder: (context, state) {
          if (state is AuthAuthenticated) {
            return const VaultPage();
          }
          return const UnlockPage();
        },
      ),
    );
  }
}
