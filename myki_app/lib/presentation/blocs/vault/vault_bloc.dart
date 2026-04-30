import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:uuid/uuid.dart';

import 'vault_event.dart';
import 'vault_state.dart';
import '../../../core/models/credential.dart';

/// Business Logic Component (BLoC) that manages the state of the user's vault.
///
/// It handles operations like loading, adding, updating, and deleting credentials,
/// as well as searching through the stored items.
class VaultBloc extends Bloc<VaultEvent, VaultState> {
  final _uuid = const Uuid();
  
  // Internal list of credentials serving as a temporary in-memory store.
  // In a production environment, this would be synchronized with an encrypted database.
  final List<Credential> _credentials = [];

  VaultBloc() : super(VaultInitial()) {
    on<VaultLoadCredentials>(_onLoadCredentials);
    on<VaultAddCredential>(_onAddCredential);
    on<VaultUpdateCredential>(_onUpdateCredential);
    on<VaultDeleteCredential>(_onDeleteCredential);
    on<VaultSearchCredentials>(_onSearchCredentials);
  }

  /// Handles loading credentials from the persistent store.
  Future<void> _onLoadCredentials(
    VaultLoadCredentials event,
    Emitter<VaultState> emit,
  ) async {
    emit(VaultLoading());
    // Simulate loading from an encrypted database
    // In a real app, this would involve decrypting the vault data
    emit(
      VaultLoaded(credentials: _credentials, filteredCredentials: _credentials),
    );
  }

  /// Handles the addition of a new credential to the vault.
  /// Generates a unique ID and sets the creation/update timestamps.
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
        totpSecret: event.totpSecret,
        createdAt: now,
        updatedAt: now,
      );
      
      // Add to internal store
      _credentials.add(credential);
      
      // Update state with the new list, maintaining any active search filters
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

  /// Handles updates to an existing credential.
  /// Updates the information and refreshes the 'updatedAt' timestamp.
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
          totpSecret: event.totpSecret,
          favorite: existing.favorite,
          createdAt: existing.createdAt,
          updatedAt: DateTime.now(),
        );
        
        // Update the item in the internal store
        _credentials[index] = updated;
        
        // Update state with the modified list
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

  /// Handles the removal of a credential from the vault.
  Future<void> _onDeleteCredential(
    VaultDeleteCredential event,
    Emitter<VaultState> emit,
  ) async {
    final currentState = state;
    if (currentState is VaultLoaded) {
      // Remove from internal store
      _credentials.removeWhere((c) => c.id == event.id);
      
      // Update state with the reduced list
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

  /// Handles searching/filtering credentials based on a query string.
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

  /// Helper method to filter a list of credentials by title, username, or URL.
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
