import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:uuid/uuid.dart';

import 'vault_event.dart';
import 'vault_state.dart';

class VaultBloc extends Bloc<VaultEvent, VaultState> {
  final _uuid = const Uuid();
  final List<Credential> _credentials = [];

  VaultBloc() : super(VaultInitial()) {
    on<VaultLoadCredentials>(_onLoadCredentials);
    on<VaultAddCredential>(_onAddCredential);
    on<VaultUpdateCredential>(_onUpdateCredential);
    on<VaultDeleteCredential>(_onDeleteCredential);
    on<VaultSearchCredentials>(_onSearchCredentials);
  }

  Future<void> _onLoadCredentials(
    VaultLoadCredentials event,
    Emitter<VaultState> emit,
  ) async {
    emit(VaultLoading());
    // In a real app, this would load from encrypted database
    emit(
      VaultLoaded(credentials: _credentials, filteredCredentials: _credentials),
    );
  }

  Future<void> _onAddCredential(
    VaultAddCredential event,
    Emitter<VaultState> emit,
  ) async {
    final currentState = state;
    if (currentState is VaultLoaded) {
      final now = DateTime.now();
      final credential = Credential(
        id: _uuid.v4(),
        title: event.title,
        username: event.username,
        password: event.password,
        url: event.url,
        notes: event.notes,
        createdAt: now,
        updatedAt: now,
      );
      _credentials.add(credential);
      emit(
        VaultLoaded(
          credentials: List.from(_credentials),
          filteredCredentials: _filterCredentials(
            _credentials,
            currentState.searchQuery,
          ),
          searchQuery: currentState.searchQuery,
        ),
      );
    }
  }

  Future<void> _onUpdateCredential(
    VaultUpdateCredential event,
    Emitter<VaultState> emit,
  ) async {
    final currentState = state;
    if (currentState is VaultLoaded) {
      final index = _credentials.indexWhere((c) => c.id == event.id);
      if (index != -1) {
        final existing = _credentials[index];
        final updated = Credential(
          id: existing.id,
          title: event.title,
          username: event.username,
          password: event.password,
          url: event.url,
          notes: event.notes,
          createdAt: existing.createdAt,
          updatedAt: DateTime.now(),
        );
        _credentials[index] = updated;
        emit(
          VaultLoaded(
            credentials: List.from(_credentials),
            filteredCredentials: _filterCredentials(
              _credentials,
              currentState.searchQuery,
            ),
            searchQuery: currentState.searchQuery,
          ),
        );
      }
    }
  }

  Future<void> _onDeleteCredential(
    VaultDeleteCredential event,
    Emitter<VaultState> emit,
  ) async {
    final currentState = state;
    if (currentState is VaultLoaded) {
      _credentials.removeWhere((c) => c.id == event.id);
      emit(
        VaultLoaded(
          credentials: List.from(_credentials),
          filteredCredentials: _filterCredentials(
            _credentials,
            currentState.searchQuery,
          ),
          searchQuery: currentState.searchQuery,
        ),
      );
    }
  }

  Future<void> _onSearchCredentials(
    VaultSearchCredentials event,
    Emitter<VaultState> emit,
  ) async {
    final currentState = state;
    if (currentState is VaultLoaded) {
      emit(
        currentState.copyWith(
          filteredCredentials: _filterCredentials(_credentials, event.query),
          searchQuery: event.query,
        ),
      );
    }
  }

  List<Credential> _filterCredentials(
    List<Credential> credentials,
    String query,
  ) {
    if (query.isEmpty) return credentials;
    final lowerQuery = query.toLowerCase();
    return credentials.where((c) {
      return c.title.toLowerCase().contains(lowerQuery) ||
          c.username.toLowerCase().contains(lowerQuery) ||
          (c.url?.toLowerCase().contains(lowerQuery) ?? false);
    }).toList();
  }
}
