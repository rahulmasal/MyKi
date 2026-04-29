import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../core/services/totp_service.dart';
import '../../core/theme/app_theme.dart';

/// Widget to display and auto-refresh TOTP codes
class TotpDisplay extends StatefulWidget {
  final String secret;
  final String? issuer;
  final String? account;
  final int digits;
  final int period;
  final String algorithm;
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
  late String _currentCode;
  late int _remainingSeconds;
  Timer? _timer;
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

    final remaining = TotpService.getRemainingSeconds(period: widget.period);

    setState(() {
      _currentCode = code;
      _remainingSeconds = remaining;
    });
  }

  void _copyCode() {
    Clipboard.setData(ClipboardData(text: _currentCode));
    setState(() => _copied = true);

    // Reset copied state after 2 seconds
    Future.delayed(const Duration(seconds: 2), () {
      if (mounted) {
        setState(() => _copied = false);
      }
    });

    widget.onCopy?.call();

    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Code copied to clipboard'),
        duration: Duration(seconds: 2),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    // Calculate progress for the circular indicator
    final progress = _remainingSeconds / widget.period;
    final isUrgent = _remainingSeconds <= 5;

    return Card(
      child: InkWell(
        onTap: _copyCode,
        borderRadius: BorderRadius.circular(16),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            children: [
              // Circular countdown indicator
              SizedBox(
                width: 48,
                height: 48,
                child: Stack(
                  alignment: Alignment.center,
                  children: [
                    CircularProgressIndicator(
                      value: progress,
                      strokeWidth: 4,
                      backgroundColor: Colors.grey.shade200,
                      valueColor: AlwaysStoppedAnimation<Color>(
                        isUrgent ? Colors.red : MykiAppTheme.primaryColor,
                      ),
                    ),
                    Text(
                      '$_remainingSeconds',
                      style: TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                        color: isUrgent ? Colors.red : MykiAppTheme.textPrimary,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 16),
              // Code display
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    if (widget.issuer != null)
                      Text(
                        widget.issuer!,
                        style: const TextStyle(
                          fontSize: 12,
                          color: MykiAppTheme.textSecondary,
                        ),
                      ),
                    const SizedBox(height: 4),
                    // Format code as "XXX XXX" for readability
                    Text(
                      _formatCode(_currentCode),
                      style: TextStyle(
                        fontSize: 28,
                        fontWeight: FontWeight.bold,
                        fontFamily: 'monospace',
                        letterSpacing: 4,
                        color: _copied
                            ? MykiAppTheme.primaryColor
                            : MykiAppTheme.textPrimary,
                      ),
                    ),
                    if (widget.account != null)
                      Text(
                        widget.account!,
                        style: const TextStyle(
                          fontSize: 12,
                          color: MykiAppTheme.textSecondary,
                        ),
                      ),
                  ],
                ),
              ),
              // Copy indicator
              Container(
                width: 40,
                height: 40,
                decoration: BoxDecoration(
                  color: _copied
                      ? MykiAppTheme.primaryColor.withValues(alpha: 0.1)
                      : Colors.grey.shade100,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Icon(
                  _copied ? Icons.check : Icons.copy,
                  color: _copied
                      ? MykiAppTheme.primaryColor
                      : MykiAppTheme.textSecondary,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  String _formatCode(String code) {
    if (code.length == 6) {
      return '${code.substring(0, 3)} ${code.substring(3)}';
    } else if (code.length == 8) {
      return '${code.substring(0, 4)} ${code.substring(4)}';
    }
    return code;
  }
}

/// Compact TOTP display for inline use
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
    return Text(
      _formatCode(_currentCode),
      style: const TextStyle(
        fontSize: 14,
        fontWeight: FontWeight.bold,
        fontFamily: 'monospace',
        letterSpacing: 2,
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
