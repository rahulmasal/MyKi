import 'dart:async';
import 'dart:convert';
import 'package:web_socket_channel/web_socket_channel.dart';
import '../../models/sync_models.dart';

/// Signaling client for WebRTC P2P discovery and negotiation.
class SignalingClient {
  final String signalingUrl;
  WebSocketChannel? _channel;
  
  final _messageController = StreamController<Map<String, dynamic>>.broadcast();
  Stream<Map<String, dynamic>> get messages => _messageController.stream;

  final _stateController = StreamController<ConnectionState>.broadcast();
  Stream<ConnectionState> get state => _stateController.stream;

  SignalingClient(this.signalingUrl);

  Future<void> connect(String deviceId, String deviceName) async {
    try {
      _stateController.add(ConnectionState.connecting);
      _channel = WebSocketChannel.connect(Uri.parse(signalingUrl));
      await _channel!.ready;

      send({
        'type': 'register',
        'deviceId': deviceId,
        'deviceName': deviceName,
        'timestamp': DateTime.now().millisecondsSinceEpoch,
      });

      _channel!.stream.listen(
        (data) {
          final message = json.decode(data as String) as Map<String, dynamic>;
          _messageController.add(message);
        },
        onError: (e) => _stateController.add(ConnectionState.error),
        onDone: () => _stateController.add(ConnectionState.disconnected),
      );

      _stateController.add(ConnectionState.connected);
    } catch (e) {
      _stateController.add(ConnectionState.error);
      rethrow;
    }
  }

  void send(Map<String, dynamic> message) {
    _channel?.sink.add(json.encode(message));
  }

  Future<void> disconnect() async {
    await _channel?.sink.close();
    _stateController.add(ConnectionState.disconnected);
  }

  void dispose() {
    disconnect();
    _messageController.close();
    _stateController.close();
  }
}
