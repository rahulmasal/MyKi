import 'package:flutter/material.dart';

import '../../core/theme/app_theme.dart';
import '../../core/models/credential.dart';
import '../../core/services/clipboard_service.dart';

/// A widget that displays a single credential entry in a list.
///
/// Shows the credential's title and username, and provides quick actions
/// like copying the password to the clipboard, toggling favorite, or deleting the entry.
class CredentialTile extends StatelessWidget {
  final Credential credential;

  /// Callback triggered when the tile is tapped (e.g., to view details).
  final VoidCallback onTap;

  /// Callback triggered when the delete action is initiated.
  final VoidCallback onDelete;

  /// Optional callback for toggling favorite status.
  final VoidCallback? onToggleFavorite;

  const CredentialTile({
    super.key,
    required this.credential,
    required this.onTap,
    required this.onDelete,
    this.onToggleFavorite,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        color: MykiAppTheme.surfaceColor,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: Colors.blueGrey.shade200, width: 1),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.02),
            blurRadius: 8,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: onTap,
          borderRadius: BorderRadius.circular(20),
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Row(
              children: [
                // Premium Icon Container: Displays the first letter of the title
                Stack(
                  children: [
                    Container(
                      width: 56,
                      height: 56,
                      decoration: BoxDecoration(
                        gradient: LinearGradient(
                          colors: [
                            MykiAppTheme.primaryColor.withValues(alpha: 0.15),
                            MykiAppTheme.primaryColor.withValues(alpha: 0.05),
                          ],
                          begin: Alignment.topLeft,
                          end: Alignment.bottomRight,
                        ),
                        borderRadius: BorderRadius.circular(16),
                        border: Border.all(
                          color: MykiAppTheme.primaryColor.withValues(
                            alpha: 0.1,
                          ),
                          width: 1,
                        ),
                      ),
                      child: Center(
                        child: Text(
                          credential.title.isNotEmpty
                              ? credential.title[0].toUpperCase()
                              : '?',
                          style: const TextStyle(
                            fontSize: 24,
                            fontWeight: FontWeight.bold,
                            color: MykiAppTheme.primaryColor,
                          ),
                        ),
                      ),
                    ),
                    // Favorite indicator
                    if (credential.favorite)
                      Positioned(
                        right: -2,
                        top: -2,
                        child: Container(
                          width: 18,
                          height: 18,
                          decoration: BoxDecoration(
                            color: MykiAppTheme.errorColor,
                            shape: BoxShape.circle,
                            border: Border.all(color: Colors.white, width: 2),
                          ),
                          child: const Icon(
                            Icons.favorite,
                            size: 10,
                            color: Colors.white,
                          ),
                        ),
                      ),
                  ],
                ),
                const SizedBox(width: 16),

                // Title and username text section
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        credential.title,
                        style: const TextStyle(
                          fontSize: 17,
                          fontWeight: FontWeight.w600,
                          color: MykiAppTheme.textPrimary,
                          letterSpacing: -0.2,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      const SizedBox(height: 4),
                      Text(
                        credential.username,
                        style: const TextStyle(
                          fontSize: 14,
                          color: MykiAppTheme.textSecondary,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ),
                ),

                // Quick Actions: Favorite, Copy and Delete
                Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    _ActionButton(
                      icon: credential.favorite
                          ? Icons.favorite
                          : Icons.favorite_border,
                      onPressed: onToggleFavorite ?? () {},
                      tooltip: credential.favorite
                          ? 'Remove from favorites'
                          : 'Add to favorites',
                      color: credential.favorite
                          ? MykiAppTheme.errorColor
                          : MykiAppTheme.textSecondary,
                    ),
                    const SizedBox(width: 4),
                    _ActionButton(
                      icon: Icons.copy_rounded,
                      onPressed: () => _copyPassword(context),
                      tooltip: 'Copy Password',
                      color: MykiAppTheme.textSecondary,
                    ),
                    const SizedBox(width: 4),
                    _ActionButton(
                      icon: Icons.delete_outline_rounded,
                      onPressed: onDelete,
                      tooltip: 'Delete',
                      color: MykiAppTheme.errorColor,
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  /// Copies the credential's password to the system clipboard and shows a confirmation snackbar.
  void _copyPassword(BuildContext context) {
    ClipboardService.copyWithAutoClear(credential.password);
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: const Row(
          children: [
            Icon(Icons.check_circle_rounded, color: Colors.white),
            SizedBox(width: 12),
            Text('Password copied (clears in 30s)'),
          ],
        ),
        backgroundColor: MykiAppTheme.successColor,
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        margin: const EdgeInsets.all(16),
        duration: const Duration(seconds: 2),
      ),
    );
  }
}

/// A private internal helper widget for the action buttons in the [CredentialTile].
class _ActionButton extends StatelessWidget {
  final IconData icon;
  final VoidCallback onPressed;
  final String tooltip;
  final Color color;

  const _ActionButton({
    required this.icon,
    required this.onPressed,
    required this.tooltip,
    required this.color,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(12),
      ),
      child: IconButton(
        icon: Icon(icon, size: 20),
        color: color,
        onPressed: onPressed,
        tooltip: tooltip,
        constraints: const BoxConstraints(minWidth: 40, minHeight: 40),
        padding: EdgeInsets.zero,
      ),
    );
  }
}
