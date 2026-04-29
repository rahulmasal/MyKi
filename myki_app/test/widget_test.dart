// This is a basic Flutter widget test.
//
// To perform an interaction with a widget in your test, use the WidgetTester
// utility in the flutter_test package. For example, you can send tap and scroll
// gestures. You can also use WidgetTester to find child widgets in the widget
// tree, read text, and verify that the values of widget properties are correct.

import 'package:flutter_test/flutter_test.dart';

import 'package:myki_app/app.dart';

void main() {
  testWidgets('App loads and shows unlock page', (WidgetTester tester) async {
    // Build our app and trigger a frame.
    await tester.pumpWidget(const MykiApp());

    // Verify that the unlock page is shown (app starts locked)
    expect(find.text('Myki'), findsOneWidget);
    expect(find.text('Enter your master password to unlock'), findsOneWidget);
  });
}
