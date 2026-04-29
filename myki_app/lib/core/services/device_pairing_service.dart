import 'dart:convert';
import 'dart:math' as math;
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'sync_service.dart';
import 'package:cryptography/cryptography.dart';

/// Device pairing info encoded in QR code
class DevicePairingInfo {
  final String deviceId;
  final String deviceName;
  final String publicKey;
  final String relayServer;
  final int timestamp;
  final String? signature; // Ed25519 signature

  DevicePairingInfo({
    required this.deviceId,
    required this.deviceName,
    required this.publicKey,
    required this.relayServer,
    required this.timestamp,
    this.signature,
  });

  Map<String, dynamic> toJson() => {
    'deviceId': deviceId,
    'deviceName': deviceName,
    'publicKey': publicKey,
    'relayServer': relayServer,
    'timestamp': timestamp,
    if (signature != null) 'signature': signature,
  };

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

  String toBase64() => base64Encode(utf8.encode(jsonEncode(toJson())));

  static DevicePairingInfo? fromBase64(String data) {
    try {
      final json = jsonDecode(utf8.decode(base64Decode(data)));
      return DevicePairingInfo.fromJson(json);
    } catch (e) {
      return null;
    }
  }

  /// Get data that should be signed (excludes the signature field itself)
  List<int> getSigningData() {
    final map = toJson();
    map.remove('signature');
    // Sort keys for consistent hashing/signing
    final sortedKeys = map.keys.toList()..sort();
    final sortedMap = {for (var k in sortedKeys) k: map[k]};
    return utf8.encode(jsonEncode(sortedMap));
  }
}

/// Service for device pairing via QR codes
class DevicePairingService extends ChangeNotifier {
  final SyncService _syncService;

  DevicePairingService(this._syncService);

  /// Generate a signed QR code data string for this device
  Future<String> generatePairingQRData() async {
    final info = DevicePairingInfo(
      deviceId: _syncService.deviceId,
      deviceName: _syncService.deviceName,
      publicKey: _syncService.publicKey,
      relayServer: _syncService.relayServerUrl,
      timestamp: DateTime.now().millisecondsSinceEpoch,
    );
    
    // Sign the info
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

  /// Widget to display QR code for other devices to scan
  Widget buildPairingQRWidget({double size = 250}) {
    return FutureBuilder<String>(
      future: generatePairingQRData(),
      builder: (context, snapshot) {
        if (!snapshot.hasData) {
          return const SizedBox(
            height: size,
            width: size,
            child: Center(child: CircularProgressIndicator()),
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

  /// Scan QR code and initiate pairing
  Future<DevicePairingInfo?> scanPairingQR(String data) async {
    final pairingInfo = DevicePairingInfo.fromBase64(data);
    if (pairingInfo == null || pairingInfo.signature == null) return null;

    // Verify signature
    final isValid = await _verifySignature(pairingInfo);
    if (!isValid) return null;

    // Validate timestamp (reject if older than 5 minutes)
    final now = DateTime.now().millisecondsSinceEpoch;
    const fiveMinutes = 5 * 60 * 1000;
    if (now - pairingInfo.timestamp > fiveMinutes) {
      return null;
    }

    // Don't pair with yourself
    if (pairingInfo.deviceId == _syncService.deviceId) {
      return null;
    }

    return pairingInfo;
  }

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

  /// Initiate secure pairing with scanned device
  Future<bool> initiatePairing(DevicePairingInfo remoteDevice) async {
    try {
      // Generate session key for this pairing
      final sessionKey = _generateSessionKey();

      // Send pairing request via relay
      final success = await _syncService.connectDevice(
        remoteDevice.deviceId,
        remoteDevice.publicKey,
        sessionKey,
      );

      if (success) {
        // Store paired device info
        await _syncService.savePairedDevice(remoteDevice);
      }

      return success;
    } catch (e) {
      return false;
    }
  }

  String _generateSessionKey() {
    // Generate cryptographically secure random session key
    final random = math.Random.secure();
    final values = Uint8List(32);
    for (int i = 0; i < 32; i++) {
      values[i] = random.nextInt(256);
    }
    return base64Encode(values);
  }
}

/// Widget for scanning QR codes to pair devices
class QRScannerWidget extends StatefulWidget {
  final Function(String) onQRScanned;
  final VoidCallback? onClose;

  const QRScannerWidget({super.key, required this.onQRScanned, this.onClose});

  @override
  State<QRScannerWidget> createState() => _QRScannerWidgetState();
}

class _QRScannerWidgetState extends State<QRScannerWidget> {
  MobileScannerController? _controller;
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
                MobileScanner(controller: _controller, onDetect: _onDetect),
                // Scan overlay
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

/// Widget for displaying this device's QR code
class MyDeviceQRWidget extends StatelessWidget {
  final String deviceName;
  final String qrData;
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
                color: Colors.black.withOpacity(0.1),
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
