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
    Navigator.of(context).pushReplacement(
      PageRouteBuilder(
        pageBuilder: (context, animation, secondaryAnimation) => const UnlockPage(),
        transitionsBuilder: (context, animation, secondaryAnimation, child) {
          return FadeTransition(opacity: animation, child: child);
        },
      ),
    );
  }

  void _addCredential() {
    Navigator.of(context).push(
      MaterialPageRoute(builder: (_) => const AddCredentialPage()),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: MykiAppTheme.backgroundColor,
      body: SafeArea(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Custom Premium App Bar
            Padding(
              padding: const EdgeInsets.fromLTRB(24, 20, 16, 12),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'My Vault',
                        style: Theme.of(context).textTheme.headlineLarge,
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'Securely stored on your device',
                        style: Theme.of(context).textTheme.bodyMedium,
                      ),
                    ],
                  ),
                  Container(
                    decoration: BoxDecoration(
                      color: MykiAppTheme.surfaceColor,
                      shape: BoxShape.circle,
                      boxShadow: [
                        BoxShadow(
                          color: Colors.black.withValues(alpha: 0.05),
                          blurRadius: 10,
                          offset: const Offset(0, 4),
                        ),
                      ],
                    ),
                    child: IconButton(
                      icon: const Icon(Icons.lock_outline_rounded),
                      color: MykiAppTheme.textPrimary,
                      onPressed: _lock,
                      tooltip: 'Lock Vault',
                    ),
                  ),
                ],
              ),
            ),
            
            // Floating Search Bar
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24.0, vertical: 12.0),
              child: Container(
                decoration: BoxDecoration(
                  boxShadow: [
                    BoxShadow(
                      color: Colors.black.withValues(alpha: 0.03),
                      blurRadius: 12,
                      offset: const Offset(0, 6),
                    ),
                  ],
                ),
                child: TextField(
                  controller: _searchController,
                  style: const TextStyle(fontWeight: FontWeight.w500),
                  decoration: InputDecoration(
                    hintText: 'Search credentials...',
                    prefixIcon: const Icon(Icons.search_rounded, color: MykiAppTheme.textHint),
                    suffixIcon: _searchController.text.isNotEmpty
                        ? IconButton(
                            icon: const Icon(Icons.close_rounded, color: MykiAppTheme.textHint),
                            onPressed: () {
                              _searchController.clear();
                              context.read<VaultBloc>().add(const VaultSearchCredentials(''));
                              FocusScope.of(context).unfocus();
                            },
                          )
                        : null,
                  ),
                  onChanged: (value) {
                    context.read<VaultBloc>().add(VaultSearchCredentials(value));
                    setState(() {}); // Update suffix icon visibility
                  },
                ),
              ),
            ),
            
            const SizedBox(height: 8),

            // Credentials List
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
                          Container(
                            padding: const EdgeInsets.all(20),
                            decoration: BoxDecoration(
                              color: MykiAppTheme.errorColor.withValues(alpha: 0.1),
                              shape: BoxShape.circle,
                            ),
                            child: const Icon(Icons.error_outline_rounded, size: 48, color: MykiAppTheme.errorColor),
                          ),
                          const SizedBox(height: 24),
                          Text(
                            'Something went wrong',
                            style: Theme.of(context).textTheme.titleLarge,
                          ),
                          const SizedBox(height: 8),
                          Text(
                            state.message,
                            style: Theme.of(context).textTheme.bodyMedium,
                          ),
                        ],
                      ),
                    );
                  }
                  
                  if (state is VaultLoaded) {
                    final credentials = state.filteredCredentials;
                    
                    if (credentials.isEmpty) {
                      return _buildEmptyState(state.searchQuery.isEmpty);
                    }
                    
                    return ListView.builder(
                      padding: const EdgeInsets.fromLTRB(24, 8, 24, 100),
                      physics: const BouncingScrollPhysics(),
                      itemCount: credentials.length,
                      itemBuilder: (context, index) {
                        final credential = credentials[index];
                        return Padding(
                          padding: const EdgeInsets.only(bottom: 16.0),
                          child: CredentialTile(
                            credential: credential,
                            onTap: () {
                              // View details
                            },
                            onDelete: () => _showDeleteConfirmation(credential.id),
                          ),
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
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _addCredential,
        backgroundColor: MykiAppTheme.primaryColor,
        elevation: 4,
        highlightElevation: 8,
        icon: const Icon(Icons.add_rounded, color: Colors.white),
        label: const Text(
          'Add Item',
          style: TextStyle(
            color: Colors.white,
            fontWeight: FontWeight.w600,
            letterSpacing: 0.2,
          ),
        ),
      ),
    );
  }

  Widget _buildEmptyState(bool isCompletelyEmpty) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Container(
            padding: const EdgeInsets.all(32),
            decoration: BoxDecoration(
              color: MykiAppTheme.primaryColor.withValues(alpha: 0.05),
              shape: BoxShape.circle,
            ),
            child: Icon(
              isCompletelyEmpty ? Icons.vpn_key_rounded : Icons.search_off_rounded,
              size: 64,
              color: MykiAppTheme.primaryColor.withValues(alpha: 0.5),
            ),
          ),
          const SizedBox(height: 32),
          Text(
            isCompletelyEmpty ? 'Your vault is empty' : 'No matches found',
            style: Theme.of(context).textTheme.titleLarge,
          ),
          const SizedBox(height: 12),
          Text(
            isCompletelyEmpty
                ? 'Add your first password to securely\nstore it on this device.'
                : 'Try adjusting your search terms.',
            textAlign: TextAlign.center,
            style: Theme.of(context).textTheme.bodyMedium,
          ),
        ],
      ),
    );
  }

  void _showDeleteConfirmation(String credentialId) {
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      builder: (context) => Container(
        padding: const EdgeInsets.all(24),
        decoration: const BoxDecoration(
          color: MykiAppTheme.surfaceColor,
          borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
        ),
        child: SafeArea(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                width: 48,
                height: 4,
                decoration: BoxDecoration(
                  color: Colors.slate.shade200,
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
              const SizedBox(height: 32),
              const Icon(Icons.warning_amber_rounded, size: 48, color: MykiAppTheme.errorColor),
              const SizedBox(height: 16),
              Text('Delete Credential?', style: Theme.of(context).textTheme.headlineLarge),
              const SizedBox(height: 12),
              Text(
                'This action cannot be undone. The credential will be permanently removed from your vault.',
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.bodyMedium,
              ),
              const SizedBox(height: 32),
              Row(
                children: [
                  Expanded(
                    child: OutlinedButton(
                      onPressed: () => Navigator.of(context).pop(),
                      style: OutlinedButton.styleFrom(
                        padding: const EdgeInsets.symmetric(vertical: 16),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
                        side: BorderSide(color: Colors.slate.shade200),
                      ),
                      child: Text('Cancel', style: TextStyle(color: MykiAppTheme.textPrimary)),
                    ),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: ElevatedButton(
                      onPressed: () {
                        context.read<VaultBloc>().add(VaultDeleteCredential(credentialId));
                        Navigator.of(context).pop();
                      },
                      style: ElevatedButton.styleFrom(
                        backgroundColor: MykiAppTheme.errorColor,
                        padding: const EdgeInsets.symmetric(vertical: 16),
                      ),
                      child: const Text('Delete'),
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}
