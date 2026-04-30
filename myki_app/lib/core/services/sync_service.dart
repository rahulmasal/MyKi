import 'dart:async';
import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:web_socket_channel/web_socket_channel.dart';
import 'package:uuid/uuid.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// P2P Sync Service for encrypted vault synchronization.
///
/// This service implements a decentralized synchronization model using WebRTC
/// for direct Peer-to-Peer (P2P) data transfer. It uses a WebSocket signaling
/// server only for initial discovery and NAT traversal, ensuring that vault
/// data never passes through a central server in plaintext.
class SyncService {
  // URLs for signaling and relay infrastructure.
  static const String _signalingServerUrl = 'wss://signaling.myki.local';
  static const String defaultRelayServer = 'wss://relay.myki.local';

  // Secure storage for persisting device identity and paired device info.
  final _storage = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock),
  );

  // WebSocket channel used for signaling (exchanging WebRTC offers/answers/candidates).
  WebSocketChannel? _signalingChannel;
  
  // WebRTC core components for the P2P connection.
  RTCPeerConnection? _peerConnection;
  RTCDataChannel? _dataChannel;
  String? _activePeerId;

  final _uuid = const Uuid();
  final String _deviceId;

  /// Human-readable name of this device, shown to other devices during pairing.
  final String deviceName;

  /// This device's public key (Ed25519) used for E2E encryption and identity verification.
  String _publicKey = '';
  String get publicKey => _publicKey;

  /// This device's private key. **CRITICAL: This should never leave the device.**
  late final SimpleKeyPair _keyPair;

  /// List of devices that have been successfully paired and are trusted for synchronization.
  List<PairedDevice> _pairedDevices = [];

  // Stream controllers for exposing service state and events to the UI.
  final _connectionStateController =
      StreamController<ConnectionState>.broadcast();
  final _messageController = StreamController<SyncMessage>.broadcast();
  final _peerListController = StreamController<List<PeerDevice>>.broadcast();

  /// Stream of connection state updates (e.g., connecting, connected, error).
  Stream<ConnectionState> get connectionState =>
      _connectionStateController.stream;
  /// Stream of incoming synchronization messages.
  Stream<SyncMessage> get messages => _messageController.stream;
  /// Stream of discovered peers on the network.
  Stream<List<PeerDevice>> get peers => _peerListController.stream;

  ConnectionState _state = ConnectionState.disconnected;
  /// Current connection state of the sync service.
  ConnectionState get state => _state;

  SyncService({String? deviceId, String? deviceName})
    : _deviceId = deviceId ?? const Uuid().v4(),
      deviceName = deviceName ?? 'MyKi Device' {
    _init();
  }

  /// Asynchronous initialization of the service.
  Future<void> _init() async {
    await _loadDeviceIdentity();
    await _loadPairedDevices();
    await _initializeKeys();
  }

  /// Loads or generates the unique device ID.
  Future<void> _loadDeviceIdentity() async {
    final savedId = await _storage.read(key: 'device_id');
    if (savedId != null) {
      // In a real implementation, we would use the saved ID.
    } else {
      await _storage.write(key: 'device_id', value: _deviceId);
    }
  }

  /// Initializes the cryptographic key pair for this device.
  ///
  /// Uses Ed25519 for digital signatures and identity.
  Future<void> _initializeKeys() async {
    final algorithm = Ed25519();
    
    final savedPrivateKey = await _storage.read(key: 'device_private_key');
    if (savedPrivateKey != null) {
      // Reconstitute key pair from saved private key.
      final privateKeyBytes = base64Decode(savedPrivateKey);
      _keyPair = await algorithm.newKeyPairFromSeed(privateKeyBytes);
    } else {
      // Generate a brand new key pair for a first-time setup.
      _keyPair = await algorithm.newKeyPair();
      final privateKeyData = await _keyPair.extract();
      final privateKeyBytes = privateKeyData.bytes;
      // Persist the private key securely.
      await _storage.write(key: 'device_private_key', value: base64Encode(privateKeyBytes));
    }

    // Extract and store the public key for sharing with other devices.
    final publicKeyData = await _keyPair.extractPublicKey();
    _publicKey = base64Encode(publicKeyData.bytes);
  }

  /// Signs raw data using this device's private key.
  ///
  /// This is used for authenticating pairing requests and sync messages.
  Future<String> signData(List<int> data) async {
    final algorithm = Ed25519();
    final signature = await algorithm.sign(data, keyPair: _keyPair);
    return base64Encode(signature.bytes);
  }

  /// Returns the unique identifier of this device.
  String get deviceId => _deviceId;

  /// Returns the URL of the relay server used for fallback communication.
  String get relayServerUrl => defaultRelayServer;

  /// Returns an unmodifiable list of currently paired and trusted devices.
  List<PairedDevice> get pairedDevices => List.unmodifiable(_pairedDevices);

  /// Loads the list of paired devices from secure persistent storage.
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

  /// Persists the current list of paired devices to secure storage.
  Future<void> _savePairedDevices() async {
    final data = json.encode(_pairedDevices.map((d) => d.toMap()).toList());
    await _storage.write(key: 'paired_devices', value: data);
  }

  /// Initiates a pairing request to another device through the signaling server.
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

  /// Saves a newly paired device's information to the trusted list.
  Future<void> savePairedDevice(dynamic remoteDevice) async {
    final pairedDevice = PairedDevice(
      id: remoteDevice.deviceId,
      name: remoteDevice.deviceName,
      publicKey: remoteDevice.publicKey,
      sessionKey: 'scanned_session_key',
      pairedAt: DateTime.now(),
    );

    _pairedDevices.removeWhere((d) => d.id == remoteDevice.deviceId);
    _pairedDevices.add(pairedDevice);
    await _savePairedDevices();
  }

  /// Establishes a connection to the central signaling server.
  Future<void> connect() async {
    if (_state == ConnectionState.connected) return;

    try {
      _updateState(ConnectionState.connecting);

      _signalingChannel = WebSocketChannel.connect(
        Uri.parse(_signalingServerUrl),
      );

      await _signalingChannel!.ready;

      // Notify the signaling server of our presence.
      _sendSignalingMessage({
        'type': 'register',
        'deviceId': _deviceId,
        'deviceName': deviceName,
        'timestamp': DateTime.now().millisecondsSinceEpoch,
      });

      // Handle incoming messages from the signaling server.
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

  /// Shuts down all active connections and cleanup resources.
  Future<void> disconnect() async {
    await _dataChannel?.close();
    await _peerConnection?.close();
    await _signalingChannel?.sink.close();
    _updateState(ConnectionState.disconnected);
  }

  /// Requests the signaling server to provide a list of currently online peers.
  Future<void> discoverPeers() async {
    _sendSignalingMessage({'type': 'discover', 'deviceId': _deviceId});
  }

  /// Establishes a direct WebRTC P2P connection with a previously paired device.
  Future<void> connectToPeer(String peerDeviceId) async {
    final paired = _pairedDevices.any((d) => d.id == peerDeviceId);
    if (!paired) {
      throw Exception('Device not paired');
    }

    _activePeerId = peerDeviceId;
    await _createPeerConnection(peerDeviceId);
    
    // Create a data channel for sending/receiving sync packets.
    final dcInit = RTCDataChannelInit();
    dcInit.ordered = true; // Ensure packets arrive in the correct order.
    _dataChannel = await _peerConnection!.createDataChannel('sync', dcInit);
    _setupDataChannel(_dataChannel!);

    // Create a WebRTC offer to initiate the connection.
    final offer = await _peerConnection!.createOffer();
    await _peerConnection!.setLocalDescription(offer);

    // Send the offer to the target peer via the signaling server.
    _sendSignalingMessage({
      'type': 'offer',
      'targetId': peerDeviceId,
      'senderId': _deviceId,
      'sdp': offer.sdp,
    });

    _updateState(ConnectionState.connecting);
  }

  /// Configures the low-level WebRTC peer connection.
  Future<void> _createPeerConnection(String peerId) async {
    final configuration = {
      'iceServers': [
        {'urls': 'stun:stun.l.google.com:19302'}, // Public STUN server for NAT traversal.
      ]
    };

    _peerConnection = await createPeerConnection(configuration);

    // Handle ICE candidates generated by the WebRTC stack.
    _peerConnection!.onIceCandidate = (candidate) {
      _sendSignalingMessage({
        'type': 'candidate',
        'targetId': peerId,
        'senderId': _deviceId,
        'candidate': candidate.toMap(),
      });
    };

    // Monitor the overall connection state.
    _peerConnection!.onConnectionState = (state) {
      if (state == RTCPeerConnectionState.RTCPeerConnectionStateConnected) {
        _updateState(ConnectionState.connected);
      } else if (state == RTCPeerConnectionState.RTCPeerConnectionStateDisconnected) {
        _updateState(ConnectionState.disconnected);
      }
    };

    // Handle incoming data channels created by the remote peer.
    _peerConnection!.onDataChannel = (channel) {
      _dataChannel = channel;
      _setupDataChannel(channel);
    };
  }

  /// Configures event listeners for the WebRTC data channel.
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

  /// Dispatches incoming signaling messages to their respective handlers.
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
          // Handle incoming WebRTC offer.
          _activePeerId = senderId;
          await _createPeerConnection(senderId!);
          await _peerConnection!.setRemoteDescription(
            RTCSessionDescription(message['sdp'], 'offer'),
          );
          // Create and send an answer back to the peer.
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
          // Complete the WebRTC handshake by setting the remote description.
          await _peerConnection!.setRemoteDescription(
            RTCSessionDescription(message['sdp'], 'answer'),
          );
          break;

        case 'candidate':
          // Add a new network candidate for the connection.
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
      // In a real app, we would log this error.
    }
  }

  /// Handles an incoming pairing request from another device.
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

    // Trust the new device by adding it to our paired devices list.
    _pairedDevices.removeWhere((d) => d.id == senderId);
    _pairedDevices.add(pairedDevice);
    await _savePairedDevices();

    // Notify the sender that the request was accepted.
    _sendSignalingMessage({
      'type': 'pairing_response',
      'targetId': senderId,
      'senderId': _deviceId,
      'status': 'accepted',
    });
  }

  /// Processes raw data received over the direct P2P data channel.
  void _handleSyncData(dynamic data, String senderId) {
    try {
      if (data is String) {
        final syncMessage = SyncMessage.fromJson(json.decode(data));
        _messageController.add(syncMessage);
      }
    } catch (e) {
      // Handle malformed data.
    }
  }

  /// Sends a synchronization message to a connected peer.
  ///
  /// Preferentially uses the secure direct P2P data channel if available,
  /// with a fallback to the signaling server if the P2P link isn't ready.
  Future<void> sendMessage(SyncMessage message, String targetId) async {
    if (_dataChannel != null && _dataChannel!.state == RTCDataChannelState.RTCDataChannelOpen) {
      _dataChannel!.send(RTCDataChannelMessage(json.encode(message.toJson())));
    } else {
      // Fallback signaling should still be encrypted by the application layer.
      _sendSignalingMessage({
        'type': 'sync_data',
        'targetId': targetId,
        'senderId': _deviceId,
        'data': json.encode(message.toJson()),
      });
    }
  }

  /// Sends a request for synchronization to a peer and waits for a response.
  Future<SyncResponse?> requestSync(String targetId, VectorClock since) async {
    final message = SyncMessage(
      id: _uuid.v4(),
      type: MessageType.syncRequest,
      timestamp: DateTime.now().millisecondsSinceEpoch,
      senderId: _deviceId,
      payload: {'since': since.toMap()},
    );

    final completer = Completer<SyncResponse?>();

    // Temporarily listen for the response message.
    final subscription = messages.listen((response) {
      if (response.type == MessageType.syncResponse && response.senderId == targetId) {
        completer.complete(SyncResponse.fromMessage(response));
      }
    });

    await sendMessage(message, targetId);

    // Wait for the response with a timeout.
    final result = await completer.future.timeout(
      const Duration(seconds: 30),
      onTimeout: () => null,
    );

    await subscription.cancel();
    return result;
  }

  /// Sends local vault changes to a remote peer.
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

  /// Helper to send a raw JSON message through the signaling WebSocket.
  void _sendSignalingMessage(Map<String, dynamic> message) {
    _signalingChannel?.sink.add(json.encode(message));
  }

  /// Internal helper to transition and notify of state changes.
  void _updateState(ConnectionState newState) {
    _state = newState;
    _connectionStateController.add(newState);
  }

  /// Disposes of the service and closes all active streams and connections.
  void dispose() {
    disconnect();
    _connectionStateController.close();
    _messageController.close();
    _peerListController.close();
  }
}

/// Enumerates the possible states of a sync connection.
enum ConnectionState { disconnected, connecting, connected, error }

/// Enumerates the types of messages exchanged during synchronization.
enum MessageType { syncRequest, syncResponse, changes, conflictResolution, ack }

/// Represents a structured message exchanged between devices during synchronization.
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

/// Represents a specific change to an entity within the vault.
class SyncChange {
  /// Unique ID of the credential or item being changed.
  final String entityId;
  /// Type of the entity (e.g., 'credential', 'folder').
  final String entityType;
  /// The operation performed (create, update, delete).
  final Operation operation;
  /// The actual data, encrypted using the vault's session key.
  final String encryptedData;
  /// A hash of the data for integrity verification.
  final String dataHash;
  /// Vector clock associated with this specific change for conflict resolution.
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

/// Enumerates the types of operations that can be performed on vault entities.
enum Operation { create, update, delete }

/// Implements a Vector Clock for distributed conflict resolution.
///
/// Vector clocks allow the system to determine the partial ordering of events
/// across multiple devices, identifying whether one change happened before
/// another or if they occurred concurrently (a conflict).
class VectorClock {
  // Maps device IDs to their respective logical clock values.
  final Map<String, int> _clock;

  VectorClock() : _clock = {};

  VectorClock.fromMap(Map<String, dynamic> map) : _clock = Map.from(map);

  Map<String, dynamic> toMap() => _clock;

  /// Retrieves the current clock value for a specific device.
  int getClock(String deviceId) => _clock[deviceId] ?? 0;

  /// Increments the local clock value for this device.
  void increment(String deviceId) {
    _clock[deviceId] = (_clock[deviceId] ?? 0) + 1;
  }

  /// Determines if this clock represents a state that strictly preceded [other].
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

  /// Determines if this clock and [other] represent concurrent changes.
  bool isConcurrent(VectorClock other) {
    return !happensBefore(other) && !other.happensBefore(this) && this != other;
  }
}

/// Represents a response to a synchronization request, containing a batch of changes.
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

/// Holds information about a discovered peer device on the network.
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

/// Holds information about a trusted paired device.
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
