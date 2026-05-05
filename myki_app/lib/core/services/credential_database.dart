import 'package:sqflite/sqflite.dart';
import 'package:path/path.dart' as p;

import 'vault_service.dart';
import '../models/credential.dart';

/// Encrypted database service for persistent credential storage.
///
/// This service manages an SQLite database where all sensitive credential fields
/// (password, notes, TOTP secret) are encrypted using AES-GCM via [VaultService]
/// before being stored. Non-sensitive fields (title, username, URL) are stored
/// in plaintext to enable search functionality without decryption.
class CredentialDatabase {
  static CredentialDatabase? _instance;
  static Database? _database;

  final VaultService _vaultService;

  CredentialDatabase._(this._vaultService);

  /// Returns the singleton instance, creating it if necessary.
  static CredentialDatabase getInstance(VaultService vaultService) {
    _instance ??= CredentialDatabase._(vaultService);
    return _instance!;
  }

  /// Returns the database instance, initializing it if necessary.
  Future<Database> get database async {
    if (_database != null && _database!.isOpen) return _database!;
    _database = await _initDatabase();
    return _database!;
  }

  /// Initializes the SQLite database and creates the credentials table.
  Future<Database> _initDatabase() async {
    final dbPath = await getDatabasesPath();
    final path = p.join(dbPath, 'myki_vault.db');

    return openDatabase(
      path,
      version: 1,
      onCreate: (db, version) async {
        await db.execute('''
          CREATE TABLE credentials (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            username TEXT NOT NULL,
            password_encrypted TEXT NOT NULL,
            url TEXT,
            notes_encrypted TEXT,
            totp_secret_encrypted TEXT,
            favorite INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
          )
        ''');
        // Index for faster search on title and username
        await db.execute(
          'CREATE INDEX idx_credentials_title ON credentials(title)',
        );
        await db.execute(
          'CREATE INDEX idx_credentials_username ON credentials(username)',
        );
        await db.execute(
          'CREATE INDEX idx_credentials_favorite ON credentials(favorite)',
        );
      },
    );
  }

  /// Encrypts a plaintext string using the vault's session key.
  /// Returns null if the vault is locked or encryption fails.
  Future<String?> _encrypt(String plaintext) async {
    try {
      return await _vaultService.encrypt(plaintext);
    } catch (_) {
      return null;
    }
  }

  /// Decrypts an encrypted string using the vault's session key.
  /// Returns null if the vault is locked or decryption fails.
  Future<String?> _decrypt(String? encrypted) async {
    if (encrypted == null || encrypted.isEmpty) return null;
    try {
      return await _vaultService.decrypt(encrypted);
    } catch (_) {
      return null;
    }
  }

  /// Inserts a new credential into the database.
  /// Sensitive fields are encrypted before storage.
  Future<void> insertCredential(Credential credential) async {
    final db = await database;

    final encryptedPassword = await _encrypt(credential.password);
    if (encryptedPassword == null) {
      throw Exception('Failed to encrypt password. Is the vault unlocked?');
    }

    final encryptedNotes = credential.notes != null
        ? await _encrypt(credential.notes!)
        : null;

    final encryptedTotpSecret = credential.totpSecret != null
        ? await _encrypt(credential.totpSecret!)
        : null;

    await db.insert('credentials', {
      'id': credential.id,
      'title': credential.title,
      'username': credential.username,
      'password_encrypted': encryptedPassword,
      'url': credential.url,
      'notes_encrypted': encryptedNotes,
      'totp_secret_encrypted': encryptedTotpSecret,
      'favorite': credential.favorite ? 1 : 0,
      'created_at': credential.createdAt.toIso8601String(),
      'updated_at': credential.updatedAt.toIso8601String(),
    }, conflictAlgorithm: ConflictAlgorithm.replace);
  }

  /// Retrieves all credentials from the database, decrypting sensitive fields.
  Future<List<Credential>> getAllCredentials() async {
    final db = await database;
    final rows = await db.query(
      'credentials',
      orderBy: 'favorite DESC, updated_at DESC',
    );

    final List<Credential> credentials = [];
    for (final row in rows) {
      final credential = await _rowToCredential(row);
      if (credential != null) {
        credentials.add(credential);
      }
    }
    return credentials;
  }

  /// Searches credentials by title, username, or URL.
  /// This works on plaintext fields only (no decryption needed for search).
  Future<List<Credential>> searchCredentials(String query) async {
    final db = await database;
    final likeQuery = '%$query%';
    final rows = await db.query(
      'credentials',
      where: 'title LIKE ? OR username LIKE ? OR url LIKE ?',
      whereArgs: [likeQuery, likeQuery, likeQuery],
      orderBy: 'favorite DESC, updated_at DESC',
    );

    final List<Credential> credentials = [];
    for (final row in rows) {
      final credential = await _rowToCredential(row);
      if (credential != null) {
        credentials.add(credential);
      }
    }
    return credentials;
  }

  /// Updates an existing credential in the database.
  Future<void> updateCredential(Credential credential) async {
    final db = await database;

    final encryptedPassword = await _encrypt(credential.password);
    if (encryptedPassword == null) {
      throw Exception('Failed to encrypt password. Is the vault unlocked?');
    }

    final encryptedNotes = credential.notes != null
        ? await _encrypt(credential.notes!)
        : null;

    final encryptedTotpSecret = credential.totpSecret != null
        ? await _encrypt(credential.totpSecret!)
        : null;

    await db.update(
      'credentials',
      {
        'title': credential.title,
        'username': credential.username,
        'password_encrypted': encryptedPassword,
        'url': credential.url,
        'notes_encrypted': encryptedNotes,
        'totp_secret_encrypted': encryptedTotpSecret,
        'favorite': credential.favorite ? 1 : 0,
        'updated_at': credential.updatedAt.toIso8601String(),
      },
      where: 'id = ?',
      whereArgs: [credential.id],
    );
  }

  /// Toggles the favorite status of a credential.
  Future<void> toggleFavorite(String credentialId) async {
    final db = await database;
    await db.rawQuery(
      'UPDATE credentials SET favorite = CASE WHEN favorite = 1 THEN 0 ELSE 1 END, updated_at = ? WHERE id = ?',
      [DateTime.now().toIso8601String(), credentialId],
    );
  }

  /// Deletes a credential from the database.
  Future<void> deleteCredential(String credentialId) async {
    final db = await database;
    await db.delete('credentials', where: 'id = ?', whereArgs: [credentialId]);
  }

  /// Converts a database row to a [Credential] object, decrypting sensitive fields.
  Future<Credential?> _rowToCredential(Map<String, dynamic> row) async {
    try {
      final password = await _decrypt(row['password_encrypted'] as String?);
      if (password == null) return null;

      final notes = await _decrypt(row['notes_encrypted'] as String?);
      final totpSecret = await _decrypt(
        row['totp_secret_encrypted'] as String?,
      );

      return Credential(
        id: row['id'] as String,
        title: row['title'] as String,
        username: row['username'] as String,
        password: password,
        url: row['url'] as String?,
        notes: notes,
        totpSecret: totpSecret,
        favorite: (row['favorite'] as int) == 1,
        createdAt: DateTime.parse(row['created_at'] as String),
        updatedAt: DateTime.parse(row['updated_at'] as String),
      );
    } catch (_) {
      // Skip credentials that fail to decrypt (e.g., vault locked)
      return null;
    }
  }

  /// Closes the database connection.
  Future<void> close() async {
    final db = await database;
    await db.close();
    _database = null;
  }

  /// Resets the singleton (useful for testing or vault lock).
  static void reset() {
    _database = null;
    _instance = null;
  }
}
