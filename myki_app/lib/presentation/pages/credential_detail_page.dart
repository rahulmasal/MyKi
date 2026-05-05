import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';

import '../../core/models/credential.dart';
import '../../core/theme/app_theme.dart';
import '../../core/services/clipboard_service.dart';
import '../blocs/vault/vault_bloc.dart';
import '../blocs/vault/vault_event.dart';
import '../widgets/totp_display.dart';

/// A page for viewing and editing a single credential's details.
///
/// Displays all credential fields with options to copy sensitive data,
/// toggle favorite status, and edit the entry.
class CredentialDetailPage extends StatefulWidget {
  final Credential credential;

  const CredentialDetailPage({super.key, required this.credential});

  @override
  State<CredentialDetailPage> createState() => _CredentialDetailPageState();
}

class _CredentialDetailPageState extends State<CredentialDetailPage> {
  late TextEditingController _titleController;
  late TextEditingController _usernameController;
  late TextEditingController _passwordController;
  late TextEditingController _urlController;
  late TextEditingController _notesController;
  late TextEditingController _totpController;

  bool _isEditing = false;
  bool _obscurePassword = true;

  @override
  void initState() {
    super.initState();
    _initializeControllers();
  }

  void _initializeControllers() {
    _titleController = TextEditingController(text: widget.credential.title);
    _usernameController = TextEditingController(
      text: widget.credential.username,
    );
    _passwordController = TextEditingController(
      text: widget.credential.password,
    );
    _urlController = TextEditingController(text: widget.credential.url);
    _notesController = TextEditingController(text: widget.credential.notes);
    _totpController = TextEditingController(text: widget.credential.totpSecret);
  }

  @override
  void dispose() {
    _titleController.dispose();
    _usernameController.dispose();
    _passwordController.dispose();
    _urlController.dispose();
    _notesController.dispose();
    _totpController.dispose();
    super.dispose();
  }

  void _toggleEdit() {
    setState(() {
      _isEditing = !_isEditing;
      if (!_isEditing) {
        _initializeControllers();
      }
    });
  }

  void _save() {
    if (_titleController.text.isEmpty || _usernameController.text.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('Title and username are required'),
          backgroundColor: MykiAppTheme.errorColor,
        ),
      );
      return;
    }

    context.read<VaultBloc>().add(
      VaultUpdateCredential(
        id: widget.credential.id,
        title: _titleController.text,
        username: _usernameController.text,
        password: _passwordController.text,
        url: _urlController.text.isEmpty ? null : _urlController.text,
        notes: _notesController.text.isEmpty ? null : _notesController.text,
        totpSecret: _totpController.text.isEmpty ? null : _totpController.text,
      ),
    );

    setState(() {
      _isEditing = false;
    });

    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Credential updated'),
        backgroundColor: MykiAppTheme.successColor,
        behavior: SnackBarBehavior.floating,
      ),
    );
  }

  void _copyToClipboard(String text, String label) {
    ClipboardService.copyWithAutoClear(text);
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('$label copied'),
        backgroundColor: MykiAppTheme.successColor,
        behavior: SnackBarBehavior.floating,
        duration: const Duration(seconds: 2),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: MykiAppTheme.backgroundColor,
      appBar: AppBar(
        title: Text(_isEditing ? 'Edit Credential' : widget.credential.title),
        backgroundColor: MykiAppTheme.backgroundColor,
        actions: [
          if (_isEditing) ...[
            TextButton(
              onPressed: _toggleEdit,
              child: const Text(
                'Cancel',
                style: TextStyle(color: MykiAppTheme.textSecondary),
              ),
            ),
            TextButton(
              onPressed: _save,
              child: const Text(
                'Save',
                style: TextStyle(
                  color: MykiAppTheme.primaryColor,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
          ] else
            IconButton(
              icon: const Icon(Icons.edit_outlined),
              onPressed: _toggleEdit,
              tooltip: 'Edit',
            ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: _isEditing
                      ? TextFormField(
                          controller: _titleController,
                          style: Theme.of(context).textTheme.headlineLarge,
                          decoration: const InputDecoration(
                            hintText: 'Title',
                            border: InputBorder.none,
                            isDense: true,
                          ),
                        )
                      : Text(
                          widget.credential.title,
                          style: Theme.of(context).textTheme.headlineLarge,
                        ),
                ),
              ],
            ),
            const SizedBox(height: 24),
            _buildFieldRow(
              label: 'Username',
              value: widget.credential.username,
              controller: _usernameController,
              isEditing: _isEditing,
              onCopy: () =>
                  _copyToClipboard(widget.credential.username, 'Username'),
              keyboardType: TextInputType.emailAddress,
            ),
            const SizedBox(height: 20),
            _buildPasswordField(),
            const SizedBox(height: 20),
            _buildFieldRow(
              label: 'Website',
              value: widget.credential.url,
              controller: _urlController,
              isEditing: _isEditing,
              onCopy: widget.credential.url != null
                  ? () => _copyToClipboard(widget.credential.url!, 'URL')
                  : null,
              keyboardType: TextInputType.url,
              prefixIcon: Icons.link_rounded,
            ),
            const SizedBox(height: 20),
            if (widget.credential.totpSecret?.isNotEmpty == true || _isEditing)
              _buildTotpSection(),
            const SizedBox(height: 20),
            _buildNotesField(),
            const SizedBox(height: 32),
            if (!_isEditing) _buildMetadata(),
          ],
        ),
      ),
    );
  }

  Widget _buildFieldRow({
    required String label,
    required String? value,
    required TextEditingController controller,
    required bool isEditing,
    VoidCallback? onCopy,
    TextInputType? keyboardType,
    IconData? prefixIcon,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: const TextStyle(
            fontSize: 13,
            fontWeight: FontWeight.w600,
            color: MykiAppTheme.textSecondary,
          ),
        ),
        const SizedBox(height: 8),
        Row(
          children: [
            Expanded(
              child: isEditing
                  ? TextFormField(
                      controller: controller,
                      keyboardType: keyboardType,
                      style: const TextStyle(fontWeight: FontWeight.w500),
                      decoration: InputDecoration(
                        prefixIcon: prefixIcon != null
                            ? Icon(prefixIcon)
                            : null,
                      ),
                    )
                  : Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 16,
                        vertical: 12,
                      ),
                      decoration: BoxDecoration(
                        color: MykiAppTheme.surfaceColor,
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(color: Colors.blueGrey.shade200),
                      ),
                      child: Row(
                        children: [
                          if (prefixIcon != null) ...[
                            Icon(
                              prefixIcon,
                              size: 18,
                              color: MykiAppTheme.textSecondary,
                            ),
                            const SizedBox(width: 8),
                          ],
                          Expanded(
                            child: Text(
                              value ?? '',
                              style: const TextStyle(
                                fontSize: 15,
                                fontWeight: FontWeight.w500,
                                color: MykiAppTheme.textPrimary,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
            ),
            if (!isEditing && onCopy != null && value?.isNotEmpty == true)
              IconButton(
                icon: const Icon(Icons.copy_rounded, size: 20),
                onPressed: onCopy,
                tooltip: 'Copy $label',
                color: MykiAppTheme.textSecondary,
              ),
          ],
        ),
      ],
    );
  }

  Widget _buildPasswordField() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Password',
          style: TextStyle(
            fontSize: 13,
            fontWeight: FontWeight.w600,
            color: MykiAppTheme.textSecondary,
          ),
        ),
        const SizedBox(height: 8),
        Row(
          children: [
            Expanded(
              child: _isEditing
                  ? TextFormField(
                      controller: _passwordController,
                      obscureText: _obscurePassword,
                      style: const TextStyle(
                        fontWeight: FontWeight.w500,
                        fontFamily: 'monospace',
                      ),
                      decoration: InputDecoration(
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
                    )
                  : Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 16,
                        vertical: 12,
                      ),
                      decoration: BoxDecoration(
                        color: MykiAppTheme.surfaceColor,
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(color: Colors.blueGrey.shade200),
                      ),
                      child: Row(
                        children: [
                          const Icon(
                            Icons.lock_outline_rounded,
                            size: 18,
                            color: MykiAppTheme.textSecondary,
                          ),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(
                              _obscurePassword
                                  ? '•' * 12
                                  : widget.credential.password,
                              style: TextStyle(
                                fontSize: 15,
                                fontWeight: FontWeight.w500,
                                fontFamily: 'monospace',
                                color: MykiAppTheme.textPrimary,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
            ),
            if (!_isEditing) ...[
              IconButton(
                icon: Icon(
                  _obscurePassword
                      ? Icons.visibility_off_rounded
                      : Icons.visibility_rounded,
                  size: 20,
                ),
                onPressed: () {
                  setState(() {
                    _obscurePassword = !_obscurePassword;
                  });
                },
                tooltip: _obscurePassword ? 'Show password' : 'Hide password',
                color: MykiAppTheme.textSecondary,
              ),
              IconButton(
                icon: const Icon(Icons.copy_rounded, size: 20),
                onPressed: () =>
                    _copyToClipboard(widget.credential.password, 'Password'),
                tooltip: 'Copy password',
                color: MykiAppTheme.textSecondary,
              ),
            ],
          ],
        ),
      ],
    );
  }

  Widget _buildTotpSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Two-Factor Authentication',
          style: TextStyle(
            fontSize: 13,
            fontWeight: FontWeight.w600,
            color: MykiAppTheme.textSecondary,
          ),
        ),
        const SizedBox(height: 8),
        if (_isEditing)
          TextFormField(
            controller: _totpController,
            style: const TextStyle(
              fontWeight: FontWeight.w500,
              fontFamily: 'monospace',
            ),
            decoration: const InputDecoration(
              hintText: 'Enter TOTP secret',
              prefixIcon: Icon(Icons.vpn_key_outlined),
            ),
          )
        else if (widget.credential.totpSecret?.isNotEmpty == true)
          TotpDisplay(
            secret: widget.credential.totpSecret!,
            issuer: widget.credential.title,
            account: widget.credential.username,
            onCopy: () {},
          ),
      ],
    );
  }

  Widget _buildNotesField() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text(
          'Notes',
          style: TextStyle(
            fontSize: 13,
            fontWeight: FontWeight.w600,
            color: MykiAppTheme.textSecondary,
          ),
        ),
        const SizedBox(height: 8),
        _isEditing
            ? TextFormField(
                controller: _notesController,
                maxLines: 4,
                style: const TextStyle(fontWeight: FontWeight.w500),
                decoration: const InputDecoration(
                  hintText: 'Additional information...',
                  alignLabelWithHint: true,
                ),
              )
            : Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: MykiAppTheme.surfaceColor,
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: Colors.blueGrey.shade200),
                ),
                child: Text(
                  widget.credential.notes?.isNotEmpty == true
                      ? widget.credential.notes!
                      : 'No notes',
                  style: TextStyle(
                    fontSize: 15,
                    fontWeight: FontWeight.w500,
                    color: widget.credential.notes?.isNotEmpty == true
                        ? MykiAppTheme.textPrimary
                        : MykiAppTheme.textHint,
                  ),
                ),
              ),
      ],
    );
  }

  Widget _buildMetadata() {
    final createdAt = widget.credential.createdAt;
    final updatedAt = widget.credential.updatedAt;

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: MykiAppTheme.surfaceColor,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.blueGrey.shade100),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Details',
            style: TextStyle(
              fontSize: 13,
              fontWeight: FontWeight.w600,
              color: MykiAppTheme.textSecondary,
            ),
          ),
          const SizedBox(height: 12),
          _metadataRow('Created', _formatDate(createdAt)),
          const SizedBox(height: 8),
          _metadataRow('Last updated', _formatDate(updatedAt)),
        ],
      ),
    );
  }

  Widget _metadataRow(String label, String value) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(
          label,
          style: const TextStyle(fontSize: 13, color: MykiAppTheme.textHint),
        ),
        Text(
          value,
          style: const TextStyle(
            fontSize: 13,
            fontWeight: FontWeight.w500,
            color: MykiAppTheme.textPrimary,
          ),
        ),
      ],
    );
  }

  String _formatDate(DateTime date) {
    return '${date.day}/${date.month}/${date.year} ${date.hour}:${date.minute.toString().padLeft(2, '0')}';
  }
}
