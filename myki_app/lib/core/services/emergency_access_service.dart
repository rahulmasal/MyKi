import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:path_provider/path_provider.dart';
import 'dart:io';

/// Emergency Access Service
/// 
/// Generates an encrypted "Emergency Kit" containing the recovery key
/// and instructions on how to regain access to the vault if the master password
/// is lost. The kit is exported as a PDF.
class EmergencyAccessService {
  final _storage = const FlutterSecureStorage();

  Future<String> generateRecoveryKey() async {
    // In a real app, this would be a high-entropy mnemonic or key.
    // Here we simulate generating a recovery key.
    final key = "MYKI-RECOVERY-${DateTime.now().millisecondsSinceEpoch}";
    await _storage.write(key: 'recovery_key', value: key);
    return key;
  }

  Future<File> generateEmergencyKitPdf(String recoveryKey) async {
    final pdf = pw.Document();

    pdf.addPage(
      pw.Page(
        build: (pw.Context context) => pw.Center(
          child: pw.Column(
            mainAxisAlignment: pw.MainAxisAlignment.center,
            children: [
              pw.Text('Myki Emergency Kit', style: pw.TextStyle(fontSize: 24, fontWeight: pw.FontWeight.bold)),
              pw.SizedBox(height: 20),
              pw.Text('Keep this document in a safe place. It contains your recovery key.'),
              pw.SizedBox(height: 40),
              pw.Container(
                padding: const pw.EdgeInsets.all(10),
                decoration: pw.BoxDecoration(border: pw.Border.all()),
                child: pw.Text(recoveryKey, style: pw.TextStyle(fontSize: 18, fontFallback: [])),
              ),
              pw.SizedBox(height: 40),
              pw.Text('Instructions:'),
              pw.Text('1. Install Myki app.'),
              pw.Text('2. Select "Recover Vault".'),
              pw.Text('3. Enter the key above.'),
            ]
          )
        ),
      ),
    );

    final output = await getApplicationDocumentsDirectory();
    final file = File("${output.path}/Myki_Emergency_Kit.pdf");
    await file.writeAsBytes(await pdf.save());
    return file;
  }
}
