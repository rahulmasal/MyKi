import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../core/services/totp_service.dart';
import '../../core/theme/app_theme.dart';

/// A widget that displays and auto-refreshes Time-based One-Time Password (TOTP) codes.
///
/// It features a modern design with a circular progress indicator showing the
/// remaining time until the code expires. Tapping the widget copies the code
/// to the clipboard.
class TotpDisplay extends StatefulWidget {
  /// The secret key used to generate the TOTP code.
  final String secret;
  
  /// The issuer (e.g., Google, GitHub) associated with the code.
  final String? issuer;
  
  /// The account name (e.g., user@email.com) associated with the code.
  final String? account;
  
  /// The number of digits in the generated code (default is 6).
  final int digits;
  
  /// The period in seconds for which a code is valid (default is 30).
  final int period;
  
  /// The hashing algorithm used (default is 'SHA1').
  final String algorithm;
  
  /// Optional callback triggered when the code is copied.
  final VoidCallback? onCopy;

  const TotpDisplay({
    super.key,
    required this.secret,
    this.issuer,
    this.account,
    this.digits = 6,
    this.period = 30,
    this.algorithm = 'SHA1',
    this.onCopy,
  });

  @override
  State<TotpDisplay> createState() => _TotpDisplayState();
}

class _TotpDisplayState extends State<TotpDisplay> {
  // The currently valid TOTP code
  late String _currentCode;
  
  // Seconds remaining before the code refreshes
  late int _remainingSeconds;
  
  // Timer that updates the code and remaining seconds every second
  Timer? _timer;
  
  // Tracks if the code was recently copied to show visual feedback
  bool _copied = false;

  @override
  void initState() {
    super.initState();
    _updateCode();
    _startTimer();
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  /// Starts a periodic timer that refreshes the display every second.
  void _startTimer() {
    _timer = Timer.periodic(const Duration(seconds: 1), (_) {
      _updateCode();
    });
  }

  /// Updates the [_currentCode] and [_remainingSeconds] by querying the [TotpService].
  void _updateCode() {
    final code = TotpService.generateCode(
      widget.secret,
      digits: widget.digits,
      period: widget.period,
    );

    final remaining = TotpService.getRemainingSeconds(period: widget.period);

    setState(() {
      _currentCode = code;
      _remainingSeconds = remaining;
    });
  }

  /// Copies the current TOTP code to the system clipboard and provides visual feedback.
  void _copyCode() {
    Clipboard.setData(ClipboardData(text: _currentCode));
    setState(() => _copied = true);

    // Reset the 'copied' state after a short delay
    Future.delayed(const Duration(seconds: 2), () {
      if (mounted) {
        setState(() => _copied = false);
      }
    });

    widget.onCopy?.call();

    // Show a success message
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: const Row(
          children: [
            Icon(Icons.check_circle_rounded, color: Colors.white),
            SizedBox(width: 12),
            Text('Code copied to clipboard'),
          ],
        ),
        backgroundColor: MykiAppTheme.successColor,
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        margin: const EdgeInsets.all(16),
        duration: const Duration(seconds: 2),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    // Calculate progress for the circular countdown indicator
    final progress = _remainingSeconds / widget.period;
    
    // Determine if the code is about to expire (less than 5 seconds)
    final isUrgent = _remainingSeconds <= 5;
    
    // Use an error color for urgent expiration states
    final accentColor = isUrgent ? MykiAppTheme.errorColor : MykiAppTheme.primaryColor;

    return Container(
      decoration: BoxDecoration(
        color: MykiAppTheme.surfaceColor,
        borderRadius: BorderRadius.circular(24),
        border: Border.all(
          color: _copied ? MykiAppTheme.successColor : Colors.blueGrey.shade200, 
          width: _copied ? 2 : 1,
        ),
        boxShadow: [
          BoxShadow(
            color: accentColor.withValues(alpha: isUrgent ? 0.1 : 0.05),
            blurRadius: 16,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: _copyCode,
          borderRadius: BorderRadius.circular(24),
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Row(
              children: [
                // Circular countdown indicator with central seconds text
                SizedBox(
                  width: 56,
                  height: 56,
                  child: Stack(
                    alignment: Alignment.center,
                    children: [
                      SizedBox(
                        width: 56,
                        height: 56,
                        child: TweenAnimationBuilder<double>(
                          duration: const Duration(milliseconds: 250),
                          curve: Curves.easeOut,
                          tween: Tween<double>(begin: progress, end: progress),
                          builder: (context, value, _) {
                            return CircularProgressIndicator(
                              value: value,
                              strokeWidth: 4,
                              backgroundColor: Colors.blueGrey.shade100,
                              valueColor: AlwaysStoppedAnimation<Color>(accentColor),
                              strokeCap: StrokeCap.round,
                            );
                          }
                        ),
                      ),
                      Text(
                        '$_remainingSeconds',
                        style: TextStyle(
                          fontSize: 18,
                          fontWeight: FontWeight.w800,
                          color: accentColor,
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 20),
                
                // Code display area with issuer and account info
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      if (widget.issuer != null)
                        Text(
                          widget.issuer!,
                          style: const TextStyle(
                            fontSize: 13,
                            fontWeight: FontWeight.w600,
                            color: MykiAppTheme.textSecondary,
                            letterSpacing: 0.5,
                          ),
                        ),
                      const SizedBox(height: 4),
                      // Format code as "XXX XXX" for improved readability
                      Text(
                        _formatCode(_currentCode),
                        style: TextStyle(
                          fontSize: 32,
                          fontWeight: FontWeight.w800,
                          fontFamily: 'monospace',
                          letterSpacing: 6,
                          color: _copied
                              ? MykiAppTheme.successColor
                              : MykiAppTheme.textPrimary,
                        ),
                      ),
                      if (widget.account != null) ...[
                        const SizedBox(height: 2),
                        Text(
                          widget.account!,
                          style: const TextStyle(
                            fontSize: 13,
                            color: MykiAppTheme.textHint,
                          ),
                        ),
                      ]
                    ],
                  ),
                ),
                
                // Visual indicator for 'copy' status
                AnimatedContainer(
                  duration: const Duration(milliseconds: 200),
                  width: 48,
                  height: 48,
                  decoration: BoxDecoration(
                    color: _copied
                        ? MykiAppTheme.successColor.withValues(alpha: 0.15)
                        : Colors.blueGrey.shade50,
                    borderRadius: BorderRadius.circular(16),
                  ),
                  child: Icon(
                    _copied ? Icons.check_rounded : Icons.copy_rounded,
                    color: _copied
                        ? MykiAppTheme.successColor
                        : MykiAppTheme.textSecondary,
                    size: 24,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  /// Helper to format the code string into groups of characters for easier reading.
  String _formatCode(String code) {
    if (code.length == 6) {
      return '${code.substring(0, 3)} ${code.substring(3)}';
    } else if (code.length == 8) {
      return '${code.substring(0, 4)} ${code.substring(4)}';
    }
    return code;
  }
}

/// A compact version of the TOTP display, suitable for inline use or lists.
class TotpDisplayCompact extends StatefulWidget {
  final String secret;
  final int digits;
  final int period;

  const TotpDisplayCompact({
    super.key,
    required this.secret,
    this.digits = 6,
    this.period = 30,
  });

  @override
  State<TotpDisplayCompact> createState() => _TotpDisplayCompactState();
}

class _TotpDisplayCompactState extends State<TotpDisplayCompact> {
  late String _currentCode;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _updateCode();
    _startTimer();
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  void _startTimer() {
    _timer = Timer.periodic(const Duration(seconds: 1), (_) {
      _updateCode();
    });
  }

  void _updateCode() {
    final code = TotpService.generateCode(
      widget.secret,
      digits: widget.digits,
      period: widget.period,
    );

    setState(() {
      _currentCode = code;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      decoration: BoxDecoration(
        color: Colors.blueGrey.shade100,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Text(
        _formatCode(_currentCode),
        style: const TextStyle(
          fontSize: 15,
          fontWeight: FontWeight.w700,
          fontFamily: 'monospace',
          letterSpacing: 2,
          color: MykiAppTheme.textPrimary,
        ),
      ),
    );
  }

  String _formatCode(String code) {
    if (code.length == 6) {
      return '${code.substring(0, 3)} ${code.substring(3)}';
    }
    return code;
  }
}
