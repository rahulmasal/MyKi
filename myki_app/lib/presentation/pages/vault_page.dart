import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';

import '../../core/theme/app_theme.dart';
import '../blocs/auth/auth_bloc.dart';
import '../blocs/auth/auth_event.dart';
import '../blocs/vault/vault_bloc.dart';
import '../blocs/vault/vault_event.dart';
import '../blocs/vault/vault_state.dart';
import '../widgets/credential_tile.dart';
import 'add_credential_page.dart';
import 'unlock_page.dart';

class VaultPage extends StatefulWidget {
  const VaultPage({super.key});

  @override
  State<VaultPage> createState() => _VaultPageState();
}

class _VaultPageState extends State<VaultPage> {
  final _searchController = TextEditingController();

  @override
  void initState() {
    super.initState();
    context.read<VaultBloc>().add(VaultLoadCredentials());
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  void _lock() {
    context.read<AuthBloc>().add(AuthLock());
    Navigator.of(
      context,
    ).pushReplacement(MaterialPageRoute(builder: (_) => const UnlockPage()));
  }

  void _addCredential() {
    Navigator.of(
      context,
    ).push(MaterialPageRoute(builder: (_) => const AddCredentialPage()));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: MykiAppTheme.backgroundColor,
      appBar: AppBar(
        title: const Text('Myki Vault'),
        backgroundColor: MykiAppTheme.backgroundColor,
        actions: [
          IconButton(
            icon: const Icon(Icons.lock_outline),
            onPressed: _lock,
            tooltip: 'Lock Vault',
          ),
        ],
      ),
      body: Column(
        children: [
          // Search bar
          Padding(
            padding: const EdgeInsets.all(16.0),
            child: TextField(
              controller: _searchController,
              decoration: InputDecoration(
                hintText: 'Search credentials...',
                filled: true,
                fillColor: Colors.white,
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                  borderSide: BorderSide.none,
                ),
                prefixIcon: const Icon(Icons.search),
                suffixIcon: _searchController.text.isNotEmpty
                    ? IconButton(
                        icon: const Icon(Icons.clear),
                        onPressed: () {
                          _searchController.clear();
                          context.read<VaultBloc>().add(
                            const VaultSearchCredentials(''),
                          );
                        },
                      )
                    : null,
              ),
              onChanged: (value) {
                context.read<VaultBloc>().add(VaultSearchCredentials(value));
              },
            ),
          ),
          // Credentials list
          Expanded(
            child: BlocBuilder<VaultBloc, VaultState>(
              builder: (context, state) {
                if (state is VaultLoading) {
                  return const Center(child: CircularProgressIndicator());
                }
                if (state is VaultError) {
                  return Center(
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(
                          Icons.error_outline,
                          size: 48,
                          color: MykiAppTheme.errorColor,
                        ),
                        const SizedBox(height: 16),
                        Text(
                          state.message,
                          style: const TextStyle(
                            color: MykiAppTheme.textSecondary,
                          ),
                        ),
                      ],
                    ),
                  );
                }
                if (state is VaultLoaded) {
                  final credentials = state.filteredCredentials;
                  if (credentials.isEmpty) {
                    return Center(
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Icon(
                            Icons.lock_outline,
                            size: 64,
                            color: MykiAppTheme.textSecondary.withValues(
                              alpha: 0.5,
                            ),
                          ),
                          const SizedBox(height: 16),
                          Text(
                            state.searchQuery.isEmpty
                                ? 'No credentials yet'
                                : 'No matching credentials',
                            style: const TextStyle(
                              fontSize: 18,
                              color: MykiAppTheme.textSecondary,
                            ),
                          ),
                          if (state.searchQuery.isEmpty) ...[
                            const SizedBox(height: 8),
                            const Text(
                              'Tap + to add your first credential',
                              style: TextStyle(
                                fontSize: 14,
                                color: MykiAppTheme.textSecondary,
                              ),
                            ),
                          ],
                        ],
                      ),
                    );
                  }
                  return ListView.builder(
                    padding: const EdgeInsets.symmetric(horizontal: 16),
                    itemCount: credentials.length,
                    itemBuilder: (context, index) {
                      final credential = credentials[index];
                      return CredentialTile(
                        credential: credential,
                        onTap: () {
                          // Navigate to detail/edit page
                        },
                        onDelete: () {
                          _showDeleteConfirmation(credential.id);
                        },
                      );
                    },
                  );
                }
                return const SizedBox.shrink();
              },
            ),
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: _addCredential,
        backgroundColor: MykiAppTheme.primaryColor,
        child: const Icon(Icons.add, color: Colors.white),
      ),
    );
  }

  void _showDeleteConfirmation(String credentialId) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Delete Credential'),
        content: const Text(
          'Are you sure you want to delete this credential? This action cannot be undone.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () {
              context.read<VaultBloc>().add(
                VaultDeleteCredential(credentialId),
              );
              Navigator.of(context).pop();
            },
            style: TextButton.styleFrom(
              foregroundColor: MykiAppTheme.errorColor,
            ),
            child: const Text('Delete'),
          ),
        ],
      ),
    );
  }
}
