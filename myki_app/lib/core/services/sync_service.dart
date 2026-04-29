import 'dart:async';
import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:web_socket_channel/web_socket_channel.dart';
import 'package:uuid/uuid.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// P2P Sync Service for encrypted vault synchronization
/// Uses WebRTC for true P2P data transfer with WebSocket signaling
class SyncService {
  static const String _signalingServerUrl = 'wss://signaling.myki.local';
  static const String defaultRelayServer = 'wss://relay.myki.local';

  final _storage = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock),
  );

  WebSocketChannel? _signalingChannel;
  
  // WebRTC components
  RTCPeerConnection? _peerConnection;
  RTCDataChannel? _dataChannel;
  String? _activePeerId;

  final _uuid = const Uuid();
  final String _deviceId;

  /// Device name for display in pairing UI
  final String deviceName;

  /// Public key for E2E encryption
  String _publicKey = '';
  String get publicKey => _publicKey;

  /// Private key (should never leave the device)
  late final SimpleKeyPair _keyPair;

  /// List of paired devices
  List<PairedDevice> _pairedDevices = [];


  final _connectionStateController =
      StreamController<ConnectionState>.broadcast();
  final _messageController = StreamController<SyncMessage>.broadcast();
  final _peerListController = StreamController<List<PeerDevice>>.broadcast();

  Stream<ConnectionState> get connectionState =>
      _connectionStateController.stream;
  Stream<SyncMessage> get messages => _messageController.stream;
  Stream<List<PeerDevice>> get peers => _peerListController.stream;

  ConnectionState _state = ConnectionState.disconnected;
  ConnectionState get state => _state;

  SyncService({String? deviceId, String? deviceName})
    : _deviceId = deviceId ?? const Uuid().v4(),
      deviceName = deviceName ?? 'MyKi Device' {
    _init();
  }

  Future<void> _init() async {
    await _loadDeviceIdentity();
    await _loadPairedDevices();
    await _initializeKeys();
  }

  Future<void> _loadDeviceIdentity() async {
    final savedId = await _storage.read(key: 'device_id');
    if (savedId != null) {
      // Logic to handle saved device ID
    } else {
      await _storage.write(key: 'device_id', value: _deviceId);
    }
  }

  Future<void> _initializeKeys() async {
    final algorithm = Ed25519();
    
    final savedPrivateKey = await _storage.read(key: 'device_private_key');
    if (savedPrivateKey != null) {
      final privateKeyBytes = base64Decode(savedPrivateKey);
      _keyPair = await algorithm.newKeyPairFromSeed(privateKeyBytes);
    } else {
      _keyPair = await algorithm.newKeyPair();
      final privateKeyData = await _keyPair.extract();
      final privateKeyBytes = privateKeyData.bytes;
      await _storage.write(key: 'device_private_key', value: base64Encode(privateKeyBytes));
    }

    final publicKeyData = await _keyPair.extractPublicKey();
    _publicKey = base64Encode(publicKeyData.bytes);
  }

  /// Sign data using the device's private key
  Future<String> signData(List<int> data) async {
    final algorithm = Ed25519();
    final signature = await algorithm.sign(data, keyPair: _keyPair);
    return base64Encode(signature.bytes);
  }

  /// Get this device's ID
  String get deviceId => _deviceId;

  /// Get relay server URL for QR pairing
  String get relayServerUrl => defaultRelayServer;

  /// Get list of paired devices
  List<PairedDevice> get pairedDevices => List.unmodifiable(_pairedDevices);

  /// Load paired devices from secure storage
  Future<void> _loadPairedDevices() async {
    try {
      final data = await _storage.read(key: 'paired_devices');
      if (data != null) {
        final List<dynamic> jsonList = json.decode(data);
        _pairedDevices =
            jsonList.map((j) => PairedDevice.fromMap(j)).toList();
      }
    } catch (e) {
      _pairedDevices = [];
    }
  }

  /// Save paired devices to secure storage
  Future<void> _savePairedDevices() async {
    final data = json.encode(_pairedDevices.map((d) => d.toMap()).toList());
    await _storage.write(key: 'paired_devices', value: data);
  }

  /// Send pairing request to a device
  Future<bool> connectDevice(String deviceId, String publicKey, String sessionKey) async {
    try {
      _sendSignalingMessage({
        'type': 'pairing_request',
        'targetId': deviceId,
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

  /// Save paired device manually
  Future<void> savePairedDevice(dynamic remoteDevice) async {
    // Basic implementation to satisfy the pairing service
    final pairedDevice = PairedDevice(
      id: remoteDevice.deviceId,
      name: remoteDevice.deviceName,
      publicKey: remoteDevice.publicKey,
      sessionKey: 'scanned_session_key', // fallback
      pairedAt: DateTime.now(),
    );

    _pairedDevices.removeWhere((d) => d.id == remoteDevice.deviceId);
    _pairedDevices.add(pairedDevice);
    await _savePairedDevices();
  }

  /// Connect to signaling server
  Future<void> connect() async {
    if (_state == ConnectionState.connected) return;

    try {
      _updateState(ConnectionState.connecting);

      _signalingChannel = WebSocketChannel.connect(
        Uri.parse(_signalingServerUrl),
      );

      await _signalingChannel!.ready;

      // Register with signaling server
      _sendSignalingMessage({
        'type': 'register',
        'deviceId': _deviceId,
        'deviceName': deviceName,
        'timestamp': DateTime.now().millisecondsSinceEpoch,
      });

      // Listen for signaling messages
      _signalingChannel!.stream.listen(
        _handleSignalingMessage,
        onError: (error) {
          _updateState(ConnectionState.error);
        },
        onDone: () {
          _updateState(ConnectionState.disconnected);
        },
      );

      _updateState(ConnectionState.connected);
    } catch (e) {
      _updateState(ConnectionState.error);
      rethrow;
    }
  }

  /// Disconnect from signaling server
  Future<void> disconnect() async {
    await _dataChannel?.close();
    await _peerConnection?.close();
    await _signalingChannel?.sink.close();
    _updateState(ConnectionState.disconnected);
  }

  /// Discover available peers
  Future<void> discoverPeers() async {
    _sendSignalingMessage({'type': 'discover', 'deviceId': _deviceId});
  }

  /// Connect to a peer device for direct sync using WebRTC
  Future<void> connectToPeer(String peerDeviceId) async {
    final paired = _pairedDevices.any((d) => d.id == peerDeviceId);
    if (!paired) {
      throw Exception('Device not paired');
    }

    _activePeerId = peerDeviceId;
    await _createPeerConnection(peerDeviceId);
    
    // Create data channel
    final dcInit = RTCDataChannelInit();
    dcInit.ordered = true;
    _dataChannel = await _peerConnection!.createDataChannel('sync', dcInit);
    _setupDataChannel(_dataChannel!);

    // Create and send offer
    final offer = await _peerConnection!.createOffer();
    await _peerConnection!.setLocalDescription(offer);

    _sendSignalingMessage({
      'type': 'offer',
      'targetId': peerDeviceId,
      'senderId': _deviceId,
      'sdp': offer.sdp,
    });

    _updateState(ConnectionState.connecting);
  }

  Future<void> _createPeerConnection(String peerId) async {
    final configuration = {
      'iceServers': [
        {'urls': 'stun:stun.l.google.com:19302'},
      ]
    };

    _peerConnection = await createPeerConnection(configuration);

    _peerConnection!.onIceCandidate = (candidate) {
      _sendSignalingMessage({
        'type': 'candidate',
        'targetId': peerId,
        'senderId': _deviceId,
        'candidate': candidate.toMap(),
      });
    };

    _peerConnection!.onConnectionState = (state) {
      if (state == RTCPeerConnectionState.RTCPeerConnectionStateConnected) {
        _updateState(ConnectionState.connected);
      } else if (state == RTCPeerConnectionState.RTCPeerConnectionStateDisconnected) {
        _updateState(ConnectionState.disconnected);
      }
    };

    _peerConnection!.onDataChannel = (channel) {
      _dataChannel = channel;
      _setupDataChannel(channel);
    };
  }

  void _setupDataChannel(RTCDataChannel channel) {
    channel.onMessage = (data) {
      _handleSyncData(data.text, _activePeerId ?? 'unknown');
    };
    channel.onDataChannelState = (state) {
      if (state == RTCDataChannelState.RTCDataChannelOpen) {
        _updateState(ConnectionState.connected);
      }
    };
  }

  void _handleSignalingMessage(dynamic data) async {
    try {
      final message = json.decode(data as String) as Map<String, dynamic>;
      final type = message['type'] as String?;
      final senderId = message['senderId'] as String?;

      switch (type) {
        case 'peer_list':
          final peers = (message['peers'] as List)
              .map((p) => PeerDevice.fromMap(p as Map<String, dynamic>))
              .toList();
          _peerListController.add(peers);
          break;

        case 'offer':
          _activePeerId = senderId;
          await _createPeerConnection(senderId!);
          await _peerConnection!.setRemoteDescription(
            RTCSessionDescription(message['sdp'], 'offer'),
          );
          final answer = await _peerConnection!.createAnswer();
          await _peerConnection!.setLocalDescription(answer);
          _sendSignalingMessage({
            'type': 'answer',
            'targetId': senderId,
            'senderId': _deviceId,
            'sdp': answer.sdp,
          });
          break;

        case 'answer':
          await _peerConnection!.setRemoteDescription(
            RTCSessionDescription(message['sdp'], 'answer'),
          );
          break;

        case 'candidate':
          final candidateMap = message['candidate'] as Map<String, dynamic>;
          await _peerConnection!.addCandidate(
            RTCIceCandidate(
              candidateMap['candidate'],
              candidateMap['sdmMid'],
              candidateMap['sdpMLineIndex'],
            ),
          );
          break;

        case 'pairing_request':
          _handlePairingRequest(message);
          break;

        case 'error':
          _updateState(ConnectionState.error);
          break;
      }
    } catch (e) {
      // Handle error
    }
  }

  void _handlePairingRequest(Map<String, dynamic> message) async {
    final senderId = message['senderId'] as String;
    final senderName = message['senderName'] as String;
    final senderPublicKey = message['publicKey'] as String;
    final sessionKey = message['sessionKey'] as String;

    final pairedDevice = PairedDevice(
      id: senderId,
      name: senderName,
      publicKey: senderPublicKey,
      sessionKey: sessionKey,
      pairedAt: DateTime.now(),
    );

    _pairedDevices.removeWhere((d) => d.id == senderId);
    _pairedDevices.add(pairedDevice);
    await _savePairedDevices();

    _sendSignalingMessage({
      'type': 'pairing_response',
      'targetId': senderId,
      'senderId': _deviceId,
      'status': 'accepted',
    });
  }

  void _handleSyncData(dynamic data, String senderId) {
    try {
      if (data is String) {
        final syncMessage = SyncMessage.fromJson(json.decode(data));
        _messageController.add(syncMessage);
      }
    } catch (e) {
      // Handle error
    }
  }

  /// Send a sync message to connected peer via WebRTC DataChannel
  Future<void> sendMessage(SyncMessage message, String targetId) async {
    if (_dataChannel != null && _dataChannel!.state == RTCDataChannelState.RTCDataChannelOpen) {
      _dataChannel!.send(RTCDataChannelMessage(json.encode(message.toJson())));
    } else {
      // Fallback to signaling if P2P not established (less secure, but functional)
      _sendSignalingMessage({
        'type': 'sync_data',
        'targetId': targetId,
        'senderId': _deviceId,
        'data': json.encode(message.toJson()),
      });
    }
  }

  /// Request sync from peer
  Future<SyncResponse?> requestSync(String targetId, VectorClock since) async {
    final message = SyncMessage(
      id: _uuid.v4(),
      type: MessageType.syncRequest,
      timestamp: DateTime.now().millisecondsSinceEpoch,
      senderId: _deviceId,
      payload: {'since': since.toMap()},
    );

    final completer = Completer<SyncResponse?>();

    final subscription = messages.listen((response) {
      if (response.type == MessageType.syncResponse && response.senderId == targetId) {
        completer.complete(SyncResponse.fromMessage(response));
      }
    });

    await sendMessage(message, targetId);

    final result = await completer.future.timeout(
      const Duration(seconds: 30),
      onTimeout: () => null,
    );

    await subscription.cancel();
    return result;
  }

  /// Send local changes to peer
  Future<void> sendChanges(String targetId, List<SyncChange> changes) async {
    final message = SyncMessage(
      id: _uuid.v4(),
      type: MessageType.changes,
      timestamp: DateTime.now().millisecondsSinceEpoch,
      senderId: _deviceId,
      payload: {'changes': changes.map((c) => c.toMap()).toList()},
    );

    await sendMessage(message, targetId);
  }

  void _sendSignalingMessage(Map<String, dynamic> message) {
    _signalingChannel?.sink.add(json.encode(message));
  }

  void _updateState(ConnectionState newState) {
    _state = newState;
    _connectionStateController.add(newState);
  }

  void dispose() {
    disconnect();
    _connectionStateController.close();
    _messageController.close();
    _peerListController.close();
  }
}

/// Connection states
enum ConnectionState { disconnected, connecting, connected, error }

/// Sync message types
enum MessageType { syncRequest, syncResponse, changes, conflictResolution, ack }

/// Sync message
class SyncMessage {
  final String id;
  final MessageType type;
  final int timestamp;
  final String senderId;
  final Map<String, dynamic> payload;

  SyncMessage({
    required this.id,
    required this.type,
    required this.timestamp,
    required this.senderId,
    required this.payload,
  });

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'type': type.name,
      'timestamp': timestamp,
      'senderId': senderId,
      'payload': payload,
    };
  }

  factory SyncMessage.fromJson(Map<String, dynamic> json) {
    return SyncMessage(
      id: json['id'] as String,
      type: MessageType.values.firstWhere(
        (e) => e.name == json['type'],
        orElse: () => MessageType.syncRequest,
      ),
      timestamp: json['timestamp'] as int,
      senderId: json['senderId'] as String,
      payload: json['payload'] as Map<String, dynamic>,
    );
  }
}

/// Sync change
class SyncChange {
  final String entityId;
  final String entityType;
  final Operation operation;
  final String encryptedData;
  final String dataHash;
  final VectorClock vectorClock;

  SyncChange({
    required this.entityId,
    required this.entityType,
    required this.operation,
    required this.encryptedData,
    required this.dataHash,
    required this.vectorClock,
  });

  Map<String, dynamic> toMap() {
    return {
      'entityId': entityId,
      'entityType': entityType,
      'operation': operation.name,
      'encryptedData': encryptedData,
      'dataHash': dataHash,
      'vectorClock': vectorClock.toMap(),
    };
  }

  factory SyncChange.fromMap(Map<String, dynamic> map) {
    return SyncChange(
      entityId: map['entityId'] as String,
      entityType: map['entityType'] as String,
      operation: Operation.values.firstWhere(
        (e) => e.name == map['operation'],
        orElse: () => Operation.update,
      ),
      encryptedData: map['encryptedData'] as String,
      dataHash: map['dataHash'] as String,
      vectorClock: VectorClock.fromMap(
        map['vectorClock'] as Map<String, dynamic>,
      ),
    );
  }
}

/// Operations
enum Operation { create, update, delete }

/// Vector clock for conflict resolution
class VectorClock {
  final Map<String, int> _clock;

  VectorClock() : _clock = {};

  VectorClock.fromMap(Map<String, dynamic> map) : _clock = Map.from(map);

  Map<String, dynamic> toMap() => _clock;

  int getClock(String deviceId) => _clock[deviceId] ?? 0;

  void increment(String deviceId) {
    _clock[deviceId] = (_clock[deviceId] ?? 0) + 1;
  }

  bool happensBefore(VectorClock other) {
    bool dominated = false;

    for (final key in {..._clock.keys, ...other._clock.keys}) {
      final a = _clock[key] ?? 0;
      final b = other._clock[key] ?? 0;

      if (a > b) return false;
      if (b > a) dominated = true;
    }

    return dominated;
  }

  bool isConcurrent(VectorClock other) {
    return !happensBefore(other) && !other.happensBefore(this) && this != other;
  }
}

/// Sync response
class SyncResponse {
  final List<SyncChange> changes;
  final VectorClock vectorClock;
  final String? conflictId;

  SyncResponse({
    required this.changes,
    required this.vectorClock,
    this.conflictId,
  });

  factory SyncResponse.fromMessage(SyncMessage message) {
    final payload = message.payload;

    return SyncResponse(
      changes:
          (payload['changes'] as List?)
              ?.map((c) => SyncChange.fromMap(c as Map<String, dynamic>))
              .toList() ??
          [],
      vectorClock: VectorClock.fromMap(
        payload['vectorClock'] as Map<String, dynamic>,
      ),
      conflictId: payload['conflictId'] as String?,
    );
  }
}

/// Peer device info
class PeerDevice {
  final String id;
  final String name;
  final DateTime lastSeen;
  final bool isOnline;

  PeerDevice({
    required this.id,
    required this.name,
    required this.lastSeen,
    required this.isOnline,
  });

  factory PeerDevice.fromMap(Map<String, dynamic> map) {
    return PeerDevice(
      id: map['id'] as String,
      name: map['name'] as String? ?? 'Unknown Device',
      lastSeen: DateTime.fromMillisecondsSinceEpoch(map['lastSeen'] as int),
      isOnline: map['isOnline'] as bool? ?? false,
    );
  }
}

/// Paired device info (from QR code pairing)
class PairedDevice {
  final String id;
  final String name;
  final String publicKey;
  final String sessionKey;
  final DateTime pairedAt;

  PairedDevice({
    required this.id,
    required this.name,
    required this.publicKey,
    required this.sessionKey,
    required this.pairedAt,
  });

  Map<String, dynamic> toMap() {
    return {
      'id': id,
      'name': name,
      'publicKey': publicKey,
      'sessionKey': sessionKey,
      'pairedAt': pairedAt.millisecondsSinceEpoch,
    };
  }

  factory PairedDevice.fromMap(Map<String, dynamic> map) {
    return PairedDevice(
      id: map['id'],
      name: map['name'],
      publicKey: map['publicKey'],
      sessionKey: map['sessionKey'],
      pairedAt: DateTime.fromMillisecondsSinceEpoch(map['pairedAt']),
    );
  }
}
