import 'dart:async';
import 'dart:convert';
import 'package:web_socket_channel/web_socket_channel.dart';
import 'package:uuid/uuid.dart';

/// P2P Sync Service for encrypted vault synchronization
/// Uses WebSocket for relay-based sync when direct P2P isn't possible
class SyncService {
  static const String _signalingServerUrl = 'wss://signaling.myki.local';

  WebSocketChannel? _signalingChannel;
  WebSocketChannel? _dataChannel;

  final _uuid = const Uuid();
  final String _deviceId;

  bool _isConnected = false;

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

  SyncService({String? deviceId}) : _deviceId = deviceId ?? const Uuid().v4();

  /// Connect to signaling server
  Future<void> connect() async {
    try {
      _signalingChannel = WebSocketChannel.connect(
        Uri.parse(_signalingServerUrl),
      );

      await _signalingChannel!.ready;

      // Register with signaling server
      _sendSignalingMessage({
        'type': 'register',
        'deviceId': _deviceId,
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

  /// Disconnect from signaling server and close connections
  Future<void> disconnect() async {
    await _dataChannel?.sink.close();
    await _signalingChannel?.sink.close();

    _isConnected = false;
    _updateState(ConnectionState.disconnected);
  }

  /// Discover available peers
  Future<List<PeerDevice>> discoverPeers() async {
    _sendSignalingMessage({'type': 'discover', 'deviceId': _deviceId});
    return [];
  }

  /// Connect to a peer device for direct sync
  Future<void> connectToPeer(String peerDeviceId) async {
    _sendSignalingMessage({
      'type': 'connect_to_peer',
      'targetId': peerDeviceId,
      'senderId': _deviceId,
    });

    _updateState(ConnectionState.connecting);
  }

  void _handleSignalingMessage(dynamic data) {
    try {
      final message = json.decode(data as String) as Map<String, dynamic>;
      final type = message['type'] as String?;

      switch (type) {
        case 'peer_list':
          final peers = (message['peers'] as List)
              .map((p) => PeerDevice.fromMap(p as Map<String, dynamic>))
              .toList();
          _peerListController.add(peers);
          break;

        case 'peer_connected':
          // Established connection to peer
          _isConnected = true;
          _updateState(ConnectionState.connected);
          break;

        case 'peer_disconnected':
          if (_isConnected) {
            _updateState(ConnectionState.disconnected);
            _isConnected = false;
          }
          break;

        case 'sync_data':
          // Handle incoming sync data
          _handleSyncData(message['data']);
          break;

        case 'error':
          _updateState(ConnectionState.error);
          break;
      }
    } catch (e) {
      // Handle parse error
    }
  }

  void _handleSyncData(dynamic data) {
    try {
      if (data is String) {
        final syncMessage = SyncMessage.fromJson(json.decode(data));
        _messageController.add(syncMessage);
      }
    } catch (e) {
      // Handle error
    }
  }

  /// Send a sync message to connected peer
  Future<void> sendMessage(SyncMessage message) async {
    if (!_isConnected) {
      // Queue for later if not connected
      return;
    }

    _sendSignalingMessage({
      'type': 'sync_data',
      'data': json.encode(message.toJson()),
    });
  }

  /// Request sync from peer
  Future<SyncResponse?> requestSync(VectorClock since) async {
    final message = SyncMessage(
      id: _uuid.v4(),
      type: MessageType.syncRequest,
      timestamp: DateTime.now().millisecondsSinceEpoch,
      senderId: _deviceId,
      payload: {'since': since.toMap()},
    );

    final completer = Completer<SyncResponse?>();

    final subscription = messages.listen((response) {
      if (response.type == MessageType.syncResponse) {
        completer.complete(SyncResponse.fromMessage(response));
      }
    });

    await sendMessage(message);

    // Timeout after 30 seconds
    final result = await completer.future.timeout(
      const Duration(seconds: 30),
      onTimeout: () => null,
    );

    await subscription.cancel();
    return result;
  }

  /// Send local changes to peer
  Future<void> sendChanges(List<SyncChange> changes) async {
    if (!_isConnected) return;

    final message = SyncMessage(
      id: _uuid.v4(),
      type: MessageType.changes,
      timestamp: DateTime.now().millisecondsSinceEpoch,
      senderId: _deviceId,
      payload: {'changes': changes.map((c) => c.toMap()).toList()},
    );

    await sendMessage(message);
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
