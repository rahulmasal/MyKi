import 'package:equatable/equatable.dart';

abstract class VaultEvent extends Equatable {
  const VaultEvent();

  @override
  List<Object?> get props => [];
}

class VaultLoadCredentials extends VaultEvent {}

class VaultAddCredential extends VaultEvent {
  final String title;
  final String username;
  final String password;
  final String? url;
  final String? notes;

  const VaultAddCredential({
    required this.title,
    required this.username,
    required this.password,
    this.url,
    this.notes,
  });

  @override
  List<Object?> get props => [title, username, password, url, notes];
}

class VaultUpdateCredential extends VaultEvent {
  final String id;
  final String title;
  final String username;
  final String password;
  final String? url;
  final String? notes;

  const VaultUpdateCredential({
    required this.id,
    required this.title,
    required this.username,
    required this.password,
    this.url,
    this.notes,
  });

  @override
  List<Object?> get props => [id, title, username, password, url, notes];
}

class VaultDeleteCredential extends VaultEvent {
  final String id;

  const VaultDeleteCredential(this.id);

  @override
  List<Object?> get props => [id];
}

class VaultSearchCredentials extends VaultEvent {
  final String query;

  const VaultSearchCredentials(this.query);

  @override
  List<Object?> get props => [query];
}
