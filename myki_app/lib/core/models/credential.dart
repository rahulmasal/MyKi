import 'package:equatable/equatable.dart';

/// Represents a single stored credential in the user's vault.
class Credential extends Equatable {
  /// Unique identifier for this credential.
  final String id;
  /// Display name of the service (e.g., "GitHub").
  final String title;
  /// Username or email used for the account.
  final String username;
  /// The secret password for the account.
  final String password;
  /// Optional website URL.
  final String? url;
  /// Optional user notes.
  final String? notes;
  /// Optional TOTP secret for 2FA.
  final String? totpSecret;
  /// Whether this is marked as a favorite.
  final bool favorite;
  /// When this entry was first created.
  final DateTime createdAt;
  /// When this entry was last modified.
  final DateTime updatedAt;

  const Credential({
    required this.id,
    required this.title,
    required this.username,
    required this.password,
    this.url,
    this.notes,
    this.totpSecret,
    this.favorite = false,
    required this.createdAt,
    required this.updatedAt,
  });

  @override
  List<Object?> get props => [id, title, username, password, url, notes, totpSecret, favorite];
}
