import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';

import '../../core/theme/app_theme.dart';
import '../blocs/vault/vault_bloc.dart';
import '../blocs/vault/vault_event.dart';

class AddCredentialPage extends StatefulWidget {
  const AddCredentialPage({super.key});

  @override
  State<AddCredentialPage> createState() => _AddCredentialPageState();
}

class _AddCredentialPageState extends State<AddCredentialPage> {
  final _formKey = GlobalKey<FormState>();
  final _titleController = TextEditingController();
  final _usernameController = TextEditingController();
  final _passwordController = TextEditingController();
  final _urlController = TextEditingController();
  final _notesController = TextEditingController();
  bool _obscurePassword = true;

  @override
  void dispose() {
    _titleController.dispose();
    _usernameController.dispose();
    _passwordController.dispose();
    _urlController.dispose();
    _notesController.dispose();
    super.dispose();
  }

  void _save() {
    if (_formKey.currentState!.validate()) {
      context.read<VaultBloc>().add(
        VaultAddCredential(
          title: _titleController.text,
          username: _usernameController.text,
          password: _passwordController.text,
          url: _urlController.text.isEmpty ? null : _urlController.text,
          notes: _notesController.text.isEmpty ? null : _notesController.text,
        ),
      );
      Navigator.of(context).pop();
    }
  }

  void _generatePassword() {
    const length = 20;
    const chars =
        'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#\$%^&*';
    final random = DateTime.now().millisecondsSinceEpoch;
    String password = '';
    for (var i = 0; i < length; i++) {
      password += chars[(random + i * 7) % chars.length];
    }
    setState(() {
      _passwordController.text = password;
      _obscurePassword = false; // Show generated password briefly
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: MykiAppTheme.backgroundColor,
      appBar: AppBar(
        title: const Text('Add Item'),
        backgroundColor: MykiAppTheme.backgroundColor,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded),
          onPressed: () => Navigator.of(context).pop(),
        ),
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: 8.0),
            child: TextButton(
              onPressed: _save,
              child: const Text(
                'Save',
                style: TextStyle(
                  color: MykiAppTheme.primaryColor,
                  fontWeight: FontWeight.bold,
                  fontSize: 16,
                ),
              ),
            ),
          ),
        ],
      ),
      body: SingleChildScrollView(
        physics: const BouncingScrollPhysics(),
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
        child: Form(
          key: _formKey,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Credential Details',
                style: Theme.of(context).textTheme.headlineLarge,
              ),
              const SizedBox(height: 8),
              Text(
                'Securely store a new password in your vault.',
                style: Theme.of(context).textTheme.bodyMedium,
              ),
              const SizedBox(height: 32),

              // Title
              _buildInputLabel('Title'),
              TextFormField(
                controller: _titleController,
                style: const TextStyle(fontWeight: FontWeight.w500),
                decoration: const InputDecoration(
                  hintText: 'e.g., Netflix, GitHub',
                  prefixIcon: Icon(Icons.title_rounded),
                ),
                validator: (value) {
                  if (value == null || value.isEmpty) {
                    return 'Please enter a title';
                  }
                  return null;
                },
              ),
              const SizedBox(height: 24),

              // Username
              _buildInputLabel('Username or Email'),
              TextFormField(
                controller: _usernameController,
                style: const TextStyle(fontWeight: FontWeight.w500),
                decoration: const InputDecoration(
                  hintText: 'user@example.com',
                  prefixIcon: Icon(Icons.person_outline_rounded),
                ),
                keyboardType: TextInputType.emailAddress,
                validator: (value) {
                  if (value == null || value.isEmpty) {
                    return 'Please enter a username';
                  }
                  return null;
                },
              ),
              const SizedBox(height: 24),

              // Password
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  _buildInputLabel('Password'),
                  TextButton.icon(
                    onPressed: _generatePassword,
                    icon: const Icon(Icons.auto_awesome_rounded, size: 16),
                    label: const Text('Generate'),
                    style: TextButton.styleFrom(
                      padding: EdgeInsets.zero,
                      visualDensity: VisualDensity.compact,
                    ),
                  ),
                ],
              ),
              TextFormField(
                controller: _passwordController,
                obscureText: _obscurePassword,
                style: const TextStyle(fontWeight: FontWeight.w500, fontFamily: 'monospace'),
                decoration: InputDecoration(
                  hintText: 'Enter password',
                  prefixIcon: const Icon(Icons.lock_outline_rounded),
                  suffixIcon: IconButton(
                    icon: Icon(
                      _obscurePassword
                          ? Icons.visibility_off_rounded
                          : Icons.visibility_rounded,
                      color: MykiAppTheme.textHint,
                    ),
                    onPressed: () {
                      setState(() {
                        _obscurePassword = !_obscurePassword;
                      });
                    },
                  ),
                ),
                validator: (value) {
                  if (value == null || value.isEmpty) {
                    return 'Please enter a password';
                  }
                  return null;
                },
              ),
              const SizedBox(height: 24),

              // URL
              _buildInputLabel('Website URL (Optional)'),
              TextFormField(
                controller: _urlController,
                style: const TextStyle(fontWeight: FontWeight.w500),
                decoration: const InputDecoration(
                  hintText: 'https://example.com',
                  prefixIcon: Icon(Icons.link_rounded),
                ),
                keyboardType: TextInputType.url,
              ),
              const SizedBox(height: 24),

              // Notes
              _buildInputLabel('Notes (Optional)'),
              TextFormField(
                controller: _notesController,
                style: const TextStyle(fontWeight: FontWeight.w500),
                decoration: const InputDecoration(
                  hintText: 'Additional information...',
                  prefixIcon: Padding(
                    padding: EdgeInsets.only(bottom: 60.0), // Align icon with top text
                    child: Icon(Icons.notes_rounded),
                  ),
                ),
                maxLines: 4,
              ),
              const SizedBox(height: 48),

              // Save button
              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  onPressed: _save,
                  icon: const Icon(Icons.save_rounded),
                  label: const Text('Save to Vault'),
                  style: ElevatedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 16),
                    elevation: 4,
                    shadowColor: MykiAppTheme.primaryColor.withValues(alpha: 0.5),
                  ),
                ),
              ),
              const SizedBox(height: 32),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildInputLabel(String text) {
    return Padding(
      padding: const EdgeInsets.only(left: 4, bottom: 8),
      child: Text(
        text,
        style: const TextStyle(
          fontSize: 14,
          fontWeight: FontWeight.w600,
          color: MykiAppTheme.textSecondary,
        ),
      ),
    );
  }
}
