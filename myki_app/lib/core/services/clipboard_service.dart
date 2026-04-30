import 'dart:async';
import 'package:flutter/services.dart';

/// Clipboard Service - manages the system clipboard with security enhancements.
///
/// This service provides a wrapper around the system clipboard to implement
/// security features such as auto-clearing sensitive data (like passwords)
/// after a specified duration.
class ClipboardService {
  static Timer? _clearTimer;

  /// Copies [text] to the clipboard and schedules an automatic clear after [duration].
  ///
  /// If another copy operation is performed before the timer expires, the previous
  /// timer is cancelled and a new one is started.
  static Future<void> copyWithAutoClear(String text, {Duration duration = const Duration(seconds: 30)}) async {
    // Cancel any existing timer to avoid premature clearing of new content.
    _clearTimer?.cancel();

    // Set the data to the clipboard.
    await Clipboard.setData(ClipboardData(text: text));

    // Schedule the clipboard to be cleared.
    _clearTimer = Timer(duration, () async {
      final currentData = await Clipboard.getData(Clipboard.kTextPlain);
      
      // Only clear if the content currently on the clipboard matches what we copied.
      // This prevents clearing content the user might have copied from elsewhere.
      if (currentData?.text == text) {
        await Clipboard.setData(const ClipboardData(text: ''));
      }
    });
  }

  /// Manually clears the clipboard.
  static Future<void> clear() async {
    _clearTimer?.cancel();
    await Clipboard.setData(const ClipboardData(text: ''));
  }
}
