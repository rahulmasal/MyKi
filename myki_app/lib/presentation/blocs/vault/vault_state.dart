import 'package:equatable/equatable.dart';

class Credential extends Equatable {
  final String id;
  final String title;
  final String username;
  final String password;
  final String? url;
  final String? notes;
  final DateTime createdAt;
  final DateTime updatedAt;

  const Credential({
    required this.id,
    required this.title,
    required this.username,
    required this.password,
    this.url,
    this.notes,
    required this.createdAt,
    required this.updatedAt,
  });

  @override
  List<Object?> get props => [id, title, username, password, url, notes];
}

abstract class VaultState extends Equatable {
  const VaultState();

  @override
  List<Object?> get props => [];
}

class VaultInitial extends VaultState {}

class VaultLoading extends VaultState {}

class VaultLoaded extends VaultState {
  final List<Credential> credentials;
  final List<Credential> filteredCredentials;
  final String searchQuery;

  const VaultLoaded({
    required this.credentials,
    required this.filteredCredentials,
    this.searchQuery = '',
  });

  @override
  List<Object?> get props => [credentials, filteredCredentials, searchQuery];

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

class VaultError extends VaultState {
  final String message;

  const VaultError(this.message);

  @override
  List<Object?> get props => [message];
}
