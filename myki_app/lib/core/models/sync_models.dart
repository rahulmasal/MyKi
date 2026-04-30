/// Enumerates the possible states of a sync connection.
enum ConnectionState { disconnected, connecting, connected, error }

/// Enumerates the types of messages exchanged during synchronization.
enum MessageType { syncRequest, syncResponse, changes, conflictResolution, ack }

/// Enumerates the types of operations that can be performed on vault entities.
enum Operation { create, update, delete }

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

/// Implements a Vector Clock for distributed conflict resolution.
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

/// Represents a response to a synchronization request.
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
      changes: (payload['changes'] as List?)
              ?.map((c) => SyncChange.fromMap(c as Map<String, dynamic>))
              .toList() ?? [],
      vectorClock: VectorClock.fromMap(
        payload['vectorClock'] as Map<String, dynamic>,
      ),
      conflictId: payload['conflictId'] as String?,
    );
  }
}

/// Information about a discovered peer device.
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

/// Information about a trusted paired device.
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
