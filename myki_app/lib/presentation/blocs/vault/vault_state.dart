import 'package:equatable/equatable.dart';
import '../../../core/models/credential.dart';

/// Base class for all states emitted by the [VaultBloc].
abstract class VaultState extends Equatable {
  const VaultState();

  @override
  List<Object?> get props => [];
}

/// The initial state before any credentials have been requested.
class VaultInitial extends VaultState {}

/// State emitted while credentials are being loaded from the secure database.
class VaultLoading extends VaultState {}

/// State emitted when the vault's credentials have been successfully loaded.
///
/// This state carries the actual data to be displayed in the UI, including
/// the full list and a filtered list for search results.
class VaultLoaded extends VaultState {
  /// The complete list of all credentials stored in the vault.
  final List<Credential> credentials;
  /// A subset of [credentials] that match the current [searchQuery].
  final List<Credential> filteredCredentials;
  /// The current string used to filter the credentials.
  final String searchQuery;

  const VaultLoaded({
    required this.credentials,
    required this.filteredCredentials,
    this.searchQuery = '',
  });

  @override
  List<Object?> get props => [credentials, filteredCredentials, searchQuery];

  /// Helper method to create a new state based on the current one with some fields updated.
  VaultLoaded copyWith({
    List<Credential>? credentials,
    List<Credential>? filteredCredentials,
    String? searchQuery,
  }) {
    return VaultLoaded(
      credentials: credentials ?? this.credentials,
      filteredCredentials: filteredCredentials ?? this.filteredCredentials,
      searchQuery: searchQuery ?? this.searchQuery,
    );
  }
}

/// State emitted when a critical error occurs while managing the vault data.
class VaultError extends VaultState {
  /// Human-readable error message.
  final String message;

  const VaultError(this.message);

  @override
  List<Object?> get props => [message];
}
