import 'dart:convert';
import 'dart:io';
import 'package:csv/csv.dart';

/// Import/Export Service
/// 
/// Handles migration from/to other password managers.
/// Supported formats: Bitwarden (CSV/JSON), LastPass (CSV), 1Password (CSV).
class ImportExportService {
  
  /// Imports credentials from a CSV file.
  /// [source] is the manager type (e.g., 'bitwarden', 'lastpass').
  Future<List<Map<String, String>>> importFromCsv(File file, String source) async {
    final input = file.openRead();
    final fields = await input
        .transform(utf8.decoder)
        .transform(const CsvToListConverter())
        .toList();

    if (fields.isEmpty) return [];

    final headers = fields[0].map((e) => e.toString().toLowerCase()).toList();
    List<Map<String, String>> results = [];

    for (var i = 1; i < fields.length; i++) {
      final row = fields[i];
      Map<String, String> entry = {};
      
      for (var j = 0; j < headers.length; j++) {
        if (j < row.length) {
          entry[headers[j]] = row[j].toString();
        }
      }
      results.add(_mapToInternal(entry, source));
    }

    return results;
  }

  /// Maps external manager fields to Myki internal format.
  Map<String, String> _mapToInternal(Map<String, String> entry, String source) {
    switch (source.toLowerCase()) {
      case 'bitwarden':
        return {
          'title': entry['name'] ?? '',
          'username': entry['login_username'] ?? '',
          'password': entry['login_password'] ?? '',
          'url': entry['login_uri'] ?? '',
          'notes': entry['notes'] ?? '',
        };
      case 'lastpass':
        return {
          'title': entry['name'] ?? '',
          'username': entry['username'] ?? '',
          'password': entry['password'] ?? '',
          'url': entry['url'] ?? '',
          'notes': entry['extra'] ?? '',
        };
      default:
        return entry;
    }
  }

  /// Exports the vault to a Bitwarden-compatible CSV format.
  Future<String> exportToBitwardenCsv(List<dynamic> credentials) async {
    List<List<dynamic>> rows = [];
    
    // Bitwarden CSV Headers
    rows.add([
      'folder', 'favorite', 'type', 'name', 'notes', 'fields', 
      'login_uri', 'login_username', 'login_password', 'login_totp'
    ]);

    for (var cred in credentials) {
      rows.add([
        '', // folder
        cred.favorite ? '1' : '0',
        'login',
        cred.title,
        cred.notes ?? '',
        '', // custom fields
        cred.url ?? '',
        cred.username,
        cred.password,
        '' // totp
      ]);
    }

    return const ListToCsvConverter().convert(rows);
  }
}
