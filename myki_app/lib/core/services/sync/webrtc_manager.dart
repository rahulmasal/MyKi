import 'dart:async';
import 'dart:convert';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import '../../models/sync_models.dart';

/// Manages WebRTC Peer-to-Peer connections and data channels.
class WebRtcManager {
  RTCPeerConnection? _peerConnection;
  RTCDataChannel? _dataChannel;
  
  final _messageController = StreamController<SyncMessage>.broadcast();
  Stream<SyncMessage> get messages => _messageController.stream;

  final _stateController = StreamController<ConnectionState>.broadcast();
  Stream<ConnectionState> get state => _stateController.stream;

  final Function(Map<String, dynamic>) onSignalingMessage;

  WebRtcManager({required this.onSignalingMessage});

  Future<void> createOffer(String peerId, String localId) async {
    await _initPeerConnection(peerId, localId);
    
    final dcInit = RTCDataChannelInit()..ordered = true;
    _dataChannel = await _peerConnection!.createDataChannel('sync', dcInit);
    _setupDataChannel(_dataChannel!);

    final offer = await _peerConnection!.createOffer();
    await _peerConnection!.setLocalDescription(offer);

    onSignalingMessage({
      'type': 'offer',
      'targetId': peerId,
      'senderId': localId,
      'sdp': offer.sdp,
    });
  }

  Future<void> handleOffer(Map<String, dynamic> message, String localId) async {
    final peerId = message['senderId'];
    await _initPeerConnection(peerId, localId);
    
    await _peerConnection!.setRemoteDescription(
      RTCSessionDescription(message['sdp'], 'offer'),
    );
    
    final answer = await _peerConnection!.createAnswer();
    await _peerConnection!.setLocalDescription(answer);
    
    onSignalingMessage({
      'type': 'answer',
      'targetId': peerId,
      'senderId': localId,
      'sdp': answer.sdp,
    });
  }

  Future<void> handleAnswer(Map<String, dynamic> message) async {
    await _peerConnection!.setRemoteDescription(
      RTCSessionDescription(message['sdp'], 'answer'),
    );
  }

  Future<void> handleCandidate(Map<String, dynamic> message) async {
    final candidateMap = message['candidate'];
    await _peerConnection!.addCandidate(
      RTCIceCandidate(
        candidateMap['candidate'],
        candidateMap['sdmMid'],
        candidateMap['sdpMLineIndex'],
      ),
    );
  }

  Future<void> _initPeerConnection(String peerId, String localId) async {
    final configuration = {
      'iceServers': [{'urls': 'stun:stun.l.google.com:19302'}]
    };

    _peerConnection = await createPeerConnection(configuration);

    _peerConnection!.onIceCandidate = (candidate) {
      onSignalingMessage({
        'type': 'candidate',
        'targetId': peerId,
        'senderId': localId,
        'candidate': candidate.toMap(),
      });
    };

    _peerConnection!.onConnectionState = (s) {
      if (s == RTCPeerConnectionState.RTCPeerConnectionStateConnected) {
        _stateController.add(ConnectionState.connected);
      } else if (s == RTCPeerConnectionState.RTCPeerConnectionStateDisconnected) {
        _stateController.add(ConnectionState.disconnected);
      }
    };

    _peerConnection!.onDataChannel = (channel) {
      _dataChannel = channel;
      _setupDataChannel(channel);
    };
  }

  void _setupDataChannel(RTCDataChannel channel) {
    channel.onMessage = (data) {
      final syncMessage = SyncMessage.fromJson(json.decode(data.text));
      _messageController.add(syncMessage);
    };
    channel.onDataChannelState = (s) {
      if (s == RTCDataChannelState.RTCDataChannelOpen) {
        _stateController.add(ConnectionState.connected);
      }
    };
  }

  Future<void> send(SyncMessage message) async {
    if (_dataChannel?.state == RTCDataChannelState.RTCDataChannelOpen) {
      _dataChannel!.send(RTCDataChannelMessage(json.encode(message.toJson())));
    } else {
      throw Exception('Data channel not open');
    }
  }

  Future<void> disconnect() async {
    await _dataChannel?.close();
    await _peerConnection?.close();
    _stateController.add(ConnectionState.disconnected);
  }

  void dispose() {
    disconnect();
    _messageController.close();
    _stateController.close();
  }
}
