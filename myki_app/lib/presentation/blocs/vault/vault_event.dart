import 'package:equatable/equatable.dart';

/// Base class for all vault-related events.
///
/// These events represent user actions performed within the credential vault,
/// such as viewing, adding, or searching for credentials.
abstract class VaultEvent extends Equatable {
  const VaultEvent();

  @override
  List<Object?> get props => [];
}

/// Dispatched to trigger the initial loading of credentials from secure storage.
class VaultLoadCredentials extends VaultEvent {}

/// Dispatched when the user wants to save a new credential to their vault.
class VaultAddCredential extends VaultEvent {
  /// The descriptive name for this credential entry (e.g., "Google").
  final String title;

  /// The username associated with the account.
  final String username;

  /// The password for the account.
  final String password;

  /// Optional URL for the service's login page.
  final String? url;

  /// Optional additional information or context.
  final String? notes;

  /// Optional TOTP secret for 2FA.
  final String? totpSecret;

  const VaultAddCredential({
    required this.title,
    required this.username,
    required this.password,
    this.url,
    this.notes,
    this.totpSecret,
  });

  @override
  List<Object?> get props => [
    title,
    username,
    password,
    url,
    notes,
    totpSecret,
  ];
}

/// Dispatched when the user updates an existing credential entry.
class VaultUpdateCredential extends VaultEvent {
  /// Unique identifier of the credential to update.
  final String id;
  final String title;
  final String username;
  final String password;
  final String? url;
  final String? notes;

  /// Optional TOTP secret for 2FA.
  final String? totpSecret;

  const VaultUpdateCredential({
    required this.id,
    required this.title,
    required this.username,
    required this.password,
    this.url,
    this.notes,
    this.totpSecret,
  });

  @override
  List<Object?> get props => [
    id,
    title,
    username,
    password,
    url,
    notes,
    totpSecret,
  ];
}

/// Dispatched when the user removes a credential from their vault.
class VaultDeleteCredential extends VaultEvent {
  /// Unique identifier of the credential to be deleted.
  final String id;

  const VaultDeleteCredential(this.id);

  @override
  List<Object?> get props => [id];
}

/// Dispatched as the user types in the search bar to filter their credential list.
class VaultSearchCredentials extends VaultEvent {
  /// The search term provided by the user.
  final String query;

  const VaultSearchCredentials(this.query);

  @override
  List<Object?> get props => [query];
}

/// Dispatched when the user toggles the favorite status of a credential.
class VaultToggleFavorite extends VaultEvent {
  /// Unique identifier of the credential to toggle favorite status.
  final String credentialId;

  const VaultToggleFavorite(this.credentialId);

  @override
  List<Object?> get props => [credentialId];
}
