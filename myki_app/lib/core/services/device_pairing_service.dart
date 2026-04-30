import 'dart:convert';
import 'dart:math' as math;
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'sync_service.dart';
import 'package:cryptography/cryptography.dart';

/// Represents the data structure for device pairing information encoded within a QR code.
///
/// This class handles the serialization and deserialization of pairing data,
/// including cryptographic signatures to ensure authenticity.
class DevicePairingInfo {
  /// Unique identifier for the device.
  final String deviceId;
  /// Human-readable name of the device.
  final String deviceName;
  /// Base64 encoded public key for secure communication.
  final String publicKey;
  /// URL of the relay server used for initial signaling.
  final String relayServer;
  /// Epoch timestamp when the pairing info was generated.
  final int timestamp;
  /// Ed25519 signature to verify that the data hasn't been tampered with.
  final String? signature;

  DevicePairingInfo({
    required this.deviceId,
    required this.deviceName,
    required this.publicKey,
    required this.relayServer,
    required this.timestamp,
    this.signature,
  });

  /// Converts the pairing info to a JSON map.
  Map<String, dynamic> toJson() => {
    'deviceId': deviceId,
    'deviceName': deviceName,
    'publicKey': publicKey,
    'relayServer': relayServer,
    'timestamp': timestamp,
    if (signature != null) 'signature': signature,
  };

  /// Creates a [DevicePairingInfo] instance from a JSON map.
  factory DevicePairingInfo.fromJson(Map<String, dynamic> json) {
    return DevicePairingInfo(
      deviceId: json['deviceId'] as String,
      deviceName: json['deviceName'] as String,
      publicKey: json['publicKey'] as String,
      relayServer: json['relayServer'] as String,
      timestamp: json['timestamp'] as int,
      signature: json['signature'] as String?,
    );
  }

  /// Encodes the pairing info as a Base64 string for QR code representation.
  String toBase64() => base64Encode(utf8.encode(jsonEncode(toJson())));

  /// Decodes a Base64 string back into a [DevicePairingInfo] instance.
  static DevicePairingInfo? fromBase64(String data) {
    try {
      final json = jsonDecode(utf8.decode(base64Decode(data)));
      return DevicePairingInfo.fromJson(json);
    } catch (e) {
      return null;
    }
  }

  /// Retrieves the raw bytes that are subject to cryptographic signing.
  ///
  /// This excludes the signature field itself and ensures consistent key ordering.
  List<int> getSigningData() {
    final map = toJson();
    map.remove('signature');
    // Sort keys for consistent hashing/signing regardless of map insertion order.
    final sortedKeys = map.keys.toList()..sort();
    final sortedMap = {for (var k in sortedKeys) k: map[k]};
    return utf8.encode(jsonEncode(sortedMap));
  }
}

/// Service responsible for managing the device pairing workflow via QR codes.
///
/// It leverages the [SyncService] for identity and secure transport, and
/// provides UI components for scanning and displaying pairing data.
class DevicePairingService extends ChangeNotifier {
  // Reference to the sync service for device identity and signing capabilities.
  final SyncService _syncService;

  DevicePairingService(this._syncService);

  /// Generates a signed Base64 string containing this device's pairing information.
  ///
  /// This data is what gets encoded into the QR code shown to other devices.
  Future<String> generatePairingQRData() async {
    final info = DevicePairingInfo(
      deviceId: _syncService.deviceId,
      deviceName: _syncService.deviceName,
      publicKey: _syncService.publicKey,
      relayServer: _syncService.relayServerUrl,
      timestamp: DateTime.now().millisecondsSinceEpoch,
    );
    
    // Cryptographically sign the pairing info using the device's private key.
    final signature = await _syncService.signData(info.getSigningData());
    
    final signedInfo = DevicePairingInfo(
      deviceId: info.deviceId,
      deviceName: info.deviceName,
      publicKey: info.publicKey,
      relayServer: info.relayServer,
      timestamp: info.timestamp,
      signature: signature,
    );
    
    return signedInfo.toBase64();
  }

  /// Builds a widget that displays a QR code for this device.
  ///
  /// Other devices can scan this QR code to initiate a pairing request.
  Widget buildPairingQRWidget({double size = 250}) {
    return FutureBuilder<String>(
      future: generatePairingQRData(),
      builder: (context, snapshot) {
        if (!snapshot.hasData) {
          return SizedBox(
            height: size,
            width: size,
            child: const Center(child: CircularProgressIndicator()),
          );
        }
        
        final qrData = snapshot.data!;
        return Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(16),
              ),
              child: QrImageView(
                data: qrData,
                version: QrVersions.auto,
                size: size,
                backgroundColor: Colors.white,
                errorCorrectionLevel: QrErrorCorrectLevel.M,
              ),
            ),
            const SizedBox(height: 16),
            Text(
              'Scan this QR code with another device',
              style: TextStyle(color: Colors.grey[600], fontSize: 14),
            ),
            const SizedBox(height: 8),
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(Icons.phone_android, size: 20, color: Colors.grey[600]),
                const SizedBox(width: 8),
                Text(
                  _syncService.deviceName,
                  style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
                ),
              ],
            ),
          ],
        );
      }
    );
  }

  /// Processes raw QR code data and returns a verified [DevicePairingInfo] if valid.
  ///
  /// This method performs several security checks:
  /// 1. Verifies the digital signature using the sender's public key.
  /// 2. Validates the timestamp to prevent replay attacks.
  /// 3. Ensures the device isn't trying to pair with itself.
  Future<DevicePairingInfo?> scanPairingQR(String data) async {
    final pairingInfo = DevicePairingInfo.fromBase64(data);
    if (pairingInfo == null || pairingInfo.signature == null) return null;

    // Verify that the signature is valid for the given data and public key.
    final isValid = await _verifySignature(pairingInfo);
    if (!isValid) return null;

    // Validate timestamp (reject if older than 5 minutes) to ensure freshness.
    final now = DateTime.now().millisecondsSinceEpoch;
    const fiveMinutes = 5 * 60 * 1000;
    if (now - pairingInfo.timestamp > fiveMinutes) {
      return null;
    }

    // Safety check: Don't pair with yourself.
    if (pairingInfo.deviceId == _syncService.deviceId) {
      return null;
    }

    return pairingInfo;
  }

  /// Verifies the Ed25519 signature of the pairing info.
  Future<bool> _verifySignature(DevicePairingInfo info) async {
    try {
      final algorithm = Ed25519();
      final publicKey = SimplePublicKey(
        base64Decode(info.publicKey),
        type: KeyPairType.ed25519,
      );
      final signature = Signature(
        base64Decode(info.signature!),
        publicKey: publicKey,
      );
      
      return await algorithm.verify(
        info.getSigningData(),
        signature: signature,
      );
    } catch (e) {
      return false;
    }
  }

  /// Initiates a secure pairing request with a remote device.
  ///
  /// This generates a session key and uses the [SyncService] to send the request
  /// through the relay server.
  Future<bool> initiatePairing(DevicePairingInfo remoteDevice) async {
    try {
      // Generate a one-time session key for this pairing handshake.
      final sessionKey = _generateSessionKey();

      // Send pairing request via the relay signaling server.
      final success = await _syncService.connectDevice(
        remoteDevice.deviceId,
        remoteDevice.publicKey,
        sessionKey,
      );

      if (success) {
        // Persistently store the paired device info if the request was sent successfully.
        await _syncService.savePairedDevice(remoteDevice);
      }

      return success;
    } catch (e) {
      return false;
    }
  }

  /// Generates a cryptographically secure random session key.
  String _generateSessionKey() {
    final random = math.Random.secure();
    final values = Uint8List(32);
    for (int i = 0; i < 32; i++) {
      values[i] = random.nextInt(256);
    }
    return base64Encode(values);
  }
}

/// A full-screen widget that provides a camera interface for scanning QR codes.
class QRScannerWidget extends StatefulWidget {
  /// Callback triggered when a QR code is successfully scanned.
  final Function(String) onQRScanned;
  /// Optional callback for when the scanner is closed without a scan.
  final VoidCallback? onClose;

  const QRScannerWidget({super.key, required this.onQRScanned, this.onClose});

  @override
  State<QRScannerWidget> createState() => _QRScannerWidgetState();
}

class _QRScannerWidgetState extends State<QRScannerWidget> {
  // Controller for the camera/scanning logic.
  MobileScannerController? _controller;
  // Flag to prevent multiple scans in quick succession.
  bool _hasScanned = false;

  @override
  void initState() {
    super.initState();
    _controller = MobileScannerController(
      detectionSpeed: DetectionSpeed.normal,
      facing: CameraFacing.back,
      torchEnabled: false,
    );
  }

  @override
  void dispose() {
    _controller?.dispose();
    super.dispose();
  }

  /// Handles the detection of a barcode/QR code.
  void _onDetect(BarcodeCapture capture) {
    if (_hasScanned) return;

    final List<Barcode> barcodes = capture.barcodes;
    for (final barcode in barcodes) {
      final value = barcode.rawValue;
      if (value != null && value.isNotEmpty) {
        setState(() => _hasScanned = true);
        widget.onQRScanned(value);
        break;
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Scan Device QR Code'),
        leading: IconButton(
          icon: const Icon(Icons.close),
          onPressed: widget.onClose ?? () => Navigator.pop(context),
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.flash_on),
            onPressed: () => _controller?.toggleTorch(),
          ),
        ],
      ),
      body: Column(
        children: [
          Expanded(
            child: Stack(
              alignment: Alignment.center,
              children: [
                // The live camera feed for scanning.
                MobileScanner(controller: _controller, onDetect: _onDetect),
                // Visual overlay to help the user frame the QR code.
                Container(
                  width: 250,
                  height: 250,
                  decoration: BoxDecoration(
                    border: Border.all(
                      color: Theme.of(context).primaryColor,
                      width: 3,
                    ),
                    borderRadius: BorderRadius.circular(16),
                  ),
                ),
              ],
            ),
          ),
          // Informational area at the bottom of the scanner.
          Container(
            padding: const EdgeInsets.all(24),
            color: Colors.grey[100],
            child: Column(
              children: [
                Icon(Icons.qr_code_scanner, size: 32, color: Colors.grey[600]),
                const SizedBox(height: 12),
                Text(
                  'Point camera at device QR code',
                  style: TextStyle(fontSize: 16, color: Colors.grey[800]),
                ),
                const SizedBox(height: 8),
                Text(
                  'The QR code contains device info to establish\nsecure peer-to-peer connection',
                  textAlign: TextAlign.center,
                  style: TextStyle(fontSize: 14, color: Colors.grey[600]),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

/// A simple widget for displaying a device's QR code and name.
class MyDeviceQRWidget extends StatelessWidget {
  /// Name of the device to display.
  final String deviceName;
  /// Raw data to be encoded in the QR code.
  final String qrData;
  /// Visual size of the QR code.
  final double size;

  const MyDeviceQRWidget({
    super.key,
    required this.deviceName,
    required this.qrData,
    this.size = 200,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: Colors.white,
            borderRadius: BorderRadius.circular(16),
            boxShadow: [
              BoxShadow(
                color: Colors.black.withValues(alpha: 0.1),
                blurRadius: 10,
                offset: const Offset(0, 4),
              ),
            ],
          ),
          child: QrImageView(
            data: qrData,
            version: QrVersions.auto,
            size: size,
            backgroundColor: Colors.white,
            errorCorrectionLevel: QrErrorCorrectLevel.M,
          ),
        ),
        const SizedBox(height: 16),
        Text(
          deviceName,
          style: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
        ),
        const SizedBox(height: 4),
        Text(
          'Show this QR to another device',
          style: TextStyle(fontSize: 14, color: Colors.grey[600]),
        ),
      ],
    );
  }
}
