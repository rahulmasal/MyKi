import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:uuid/uuid.dart';

import 'vault_event.dart';
import 'vault_state.dart';
import '../../../core/models/credential.dart';
import '../../../core/services/credential_database.dart';
import '../../../core/services/vault_service.dart';

/// Business Logic Component (BLoC) that manages the state of the user's vault.
///
/// It handles loading, adding, updating, deleting credentials, searching,
/// and toggling favorites. Uses [CredentialDatabase] for persistent encrypted storage.
class VaultBloc extends Bloc<VaultEvent, VaultState> {
  final _uuid = const Uuid();

  // Internal list of credentials serving as a temporary in-memory cache.
  final List<Credential> _credentials = [];

  // Database instance for persistent storage
  CredentialDatabase? _database;

  // Reference to VaultService for encryption operations
  final VaultService? _vaultService;

  VaultBloc({VaultService? vaultService})
    : _vaultService = vaultService,
      super(VaultInitial()) {
    on<VaultLoadCredentials>(_onLoadCredentials);
    on<VaultAddCredential>(_onAddCredential);
    on<VaultUpdateCredential>(_onUpdateCredential);
    on<VaultDeleteCredential>(_onDeleteCredential);
    on<VaultSearchCredentials>(_onSearchCredentials);
    on<VaultToggleFavorite>(_onToggleFavorite);
  }

  /// Initializes the database if not already initialized.
  Future<CredentialDatabase> _getDatabase() async {
    if (_database == null && _vaultService != null) {
      _database = CredentialDatabase.getInstance(_vaultService);
    }
    return _database!;
  }

  /// Handles loading credentials from persistent storage.
  Future<void> _onLoadCredentials(
    VaultLoadCredentials event,
    Emitter<VaultState> emit,
  ) async {
    emit(VaultLoading());
    try {
      final db = await _getDatabase();
      final credentials = await db.getAllCredentials();

      _credentials.clear();
      _credentials.addAll(credentials);

      emit(
        VaultLoaded(
          credentials: List.from(_credentials),
          filteredCredentials: List.from(_credentials),
        ),
      );
    } catch (e) {
      // Fallback to empty list if database fails
      emit(
        VaultLoaded(
          credentials: List.from(_credentials),
          filteredCredentials: List.from(_credentials),
        ),
      );
    }
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
        favorite: false,
        createdAt: now,
        updatedAt: now,
      );

      // Add to internal store
      _credentials.add(credential);

      // Persist to database
      try {
        final db = await _getDatabase();
        await db.insertCredential(credential);
      } catch (e) {
        // Continue even if DB fails - data is in memory
      }

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

        // Persist to database
        try {
          final db = await _getDatabase();
          await db.updateCredential(updated);
        } catch (e) {
          // Continue even if DB fails - data is in memory
        }

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

      // Remove from database
      try {
        final db = await _getDatabase();
        await db.deleteCredential(event.id);
      } catch (e) {
        // Continue even if DB fails - data is removed from memory
      }

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

  /// Handles toggling the favorite status of a credential.
  Future<void> _onToggleFavorite(
    VaultToggleFavorite event,
    Emitter<VaultState> emit,
  ) async {
    final currentState = state;
    if (currentState is VaultLoaded) {
      final index = _credentials.indexWhere((c) => c.id == event.credentialId);
      if (index != -1) {
        final existing = _credentials[index];
        final updated = Credential(
          id: existing.id,
          title: existing.title,
          username: existing.username,
          password: existing.password,
          url: existing.url,
          notes: existing.notes,
          totpSecret: existing.totpSecret,
          favorite: !existing.favorite,
          createdAt: existing.createdAt,
          updatedAt: DateTime.now(),
        );

        // Update the item in the internal store
        _credentials[index] = updated;

        // Persist to database
        try {
          final db = await _getDatabase();
          await db.toggleFavorite(event.credentialId);
        } catch (e) {
          // Continue even if DB fails - data is in memory
        }

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

  /// Helper method to filter a list of credentials by title, username, or URL.
  /// Favorites are always shown first.
  List<Credential> _filterCredentials(
    List<Credential> credentials,
    String query,
  ) {
    List<Credential> filtered;
    if (query.isEmpty) {
      filtered = credentials;
    } else {
      final lowerQuery = query.toLowerCase();
      filtered = credentials.where((c) {
        return c.title.toLowerCase().contains(lowerQuery) ||
            c.username.toLowerCase().contains(lowerQuery) ||
            (c.url?.toLowerCase().contains(lowerQuery) ?? false);
      }).toList();
    }

    // Sort: favorites first, then by updatedAt descending
    filtered.sort((a, b) {
      if (a.favorite != b.favorite) {
        return a.favorite ? -1 : 1;
      }
      return b.updatedAt.compareTo(a.updatedAt);
    });

    return filtered;
  }
}
