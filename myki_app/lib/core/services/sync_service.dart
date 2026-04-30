import 'dart:async';
import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:uuid/uuid.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../models/sync_models.dart';
import 'sync/signaling_client.dart';
import 'sync/webrtc_manager.dart';

/// P2P Sync Service for encrypted vault synchronization.
///
/// Coordinates signaling, WebRTC P2P connections, and vault data exchange.
class SyncService {
  static const String _signalingServerUrl = 'wss://signaling.myki.local';

  final _storage = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock),
  );

  late final SignalingClient _signaling;
  late final WebRtcManager _webrtc;
  
  final String _deviceId;
  final String deviceName;
  String _publicKey = '';
  late final SimpleKeyPair _keyPair;

  String get deviceId => _deviceId;
  String get publicKey => _publicKey;
  String get relayServerUrl => 'wss://relay.myki.local';

  List<PairedDevice> _pairedDevices = [];

  // Public Streams
  final _peerListController = StreamController<List<PeerDevice>>.broadcast();
  Stream<List<PeerDevice>> get peers => _peerListController.stream;
  Stream<SyncMessage> get messages => _webrtc.messages;
  Stream<ConnectionState> get connectionState => _webrtc.state;

  SyncService({String? deviceId, String? deviceName})
    : _deviceId = deviceId ?? const Uuid().v4(),
      deviceName = deviceName ?? 'MyKi Device' {
    _signaling = SignalingClient(_signalingServerUrl);
    _webrtc = WebRtcManager(onSignalingMessage: (msg) => _signaling.send(msg));
    _init();
  }

  Future<void> _init() async {
    await _loadPairedDevices();
    await _initializeKeys();
    
    _signaling.messages.listen(_handleSignalingMessage);
  }

  Future<void> _initializeKeys() async {
    final algorithm = Ed25519();
    final savedPrivateKey = await _storage.read(key: 'device_private_key');
    
    if (savedPrivateKey != null) {
      _keyPair = await algorithm.newKeyPairFromSeed(base64Decode(savedPrivateKey));
    } else {
      _keyPair = await algorithm.newKeyPair();
      final privateKey = (await _keyPair.extract()).bytes;
      await _storage.write(key: 'device_private_key', value: base64Encode(privateKey));
    }

    final publicKeyData = await _keyPair.extractPublicKey();
    _publicKey = base64Encode(publicKeyData.bytes);
  }

  Future<String> signData(List<int> data) async {
    final algorithm = Ed25519();
    final signature = await algorithm.sign(data, keyPair: _keyPair);
    return base64Encode(signature.bytes);
  }

  Future<bool> connectDevice(String targetDeviceId, String targetPublicKey, String sessionKey) async {
    try {
      _signaling.send({
        'type': 'pairing_request',
        'targetId': targetDeviceId,
        'senderId': _deviceId,
        'senderName': deviceName,
        'publicKey': _publicKey,
        'sessionKey': sessionKey,
      });
      return true;
    } catch (e) {
      return false;
    }
  }

  Future<void> savePairedDevice(dynamic remoteDevice) async {
    final pairedDevice = PairedDevice(
      id: remoteDevice.deviceId,
      name: remoteDevice.deviceName,
      publicKey: remoteDevice.publicKey,
      sessionKey: 'scanned_session_key',
      pairedAt: DateTime.now(),
    );

    _pairedDevices.removeWhere((d) => d.id == pairedDevice.id);
    _pairedDevices.add(pairedDevice);
    await _savePairedDevices();
  }

  Future<void> connect() async {
    await _signaling.connect(_deviceId, deviceName);
  }

  Future<void> disconnect() async {
    await _webrtc.disconnect();
    await _signaling.disconnect();
  }

  Future<void> discoverPeers() async {
    _signaling.send({'type': 'discover', 'deviceId': _deviceId});
  }

  Future<void> connectToPeer(String peerDeviceId) async {
    if (!_pairedDevices.any((d) => d.id == peerDeviceId)) {
      throw Exception('Device not paired');
    }
    await _webrtc.createOffer(peerDeviceId, _deviceId);
  }

  void _handleSignalingMessage(Map<String, dynamic> message) async {
    final type = message['type'] as String?;
    
    switch (type) {
      case 'peer_list':
        final peers = (message['peers'] as List)
            .map((p) => PeerDevice.fromMap(p as Map<String, dynamic>))
            .toList();
        _peerListController.add(peers);
        break;
      case 'offer':
        await _webrtc.handleOffer(message, _deviceId);
        break;
      case 'answer':
        await _webrtc.handleAnswer(message);
        break;
      case 'candidate':
        await _webrtc.handleCandidate(message);
        break;
      case 'pairing_request':
        _handlePairingRequest(message);
        break;
    }
  }

  void _handlePairingRequest(Map<String, dynamic> message) async {
    final pairedDevice = PairedDevice(
      id: message['senderId'],
      name: message['senderName'],
      publicKey: message['publicKey'],
      sessionKey: message['sessionKey'],
      pairedAt: DateTime.now(),
    );

    _pairedDevices.removeWhere((d) => d.id == pairedDevice.id);
    _pairedDevices.add(pairedDevice);
    await _savePairedDevices();

    _signaling.send({
      'type': 'pairing_response',
      'targetId': pairedDevice.id,
      'senderId': _deviceId,
      'status': 'accepted',
    });
  }

  Future<void> _loadPairedDevices() async {
    final data = await _storage.read(key: 'paired_devices');
    if (data != null) {
      final List jsonList = json.decode(data);
      _pairedDevices = jsonList.map((j) => PairedDevice.fromMap(j)).toList();
    }
  }

  Future<void> _savePairedDevices() async {
    final data = json.encode(_pairedDevices.map((d) => d.toMap()).toList());
    await _storage.write(key: 'paired_devices', value: data);
  }

  Future<void> sendMessage(SyncMessage message, String targetId) async {
    try {
      await _webrtc.send(message);
    } catch (e) {
      // Fallback to signaling if P2P fails (should still be app-layer encrypted)
      _signaling.send({
        'type': 'sync_data',
        'targetId': targetId,
        'senderId': _deviceId,
        'data': json.encode(message.toJson()),
      });
    }
  }

  void dispose() {
    _signaling.dispose();
    _webrtc.dispose();
    _peerListController.close();
  }
}
