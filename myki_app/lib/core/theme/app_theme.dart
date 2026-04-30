import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

/// A collection of raw colors and gradients used throughout the Myki application.
///
/// This class acts as a central repository for the brand's visual identity,
/// ensuring consistency across different UI components.
class MykiAppTheme {
  // Private constructor to prevent instantiation.
  MykiAppTheme._();

  // Refined Premium Color Palette
  static const Color primaryColor = Color(0xFF4F46E5); // Indigo 600
  static const Color secondaryColor = Color(0xFF0F172A); // Slate 900
  static const Color accentColor = Color(0xFF10B981); // Emerald 500
  
  static const Color errorColor = Color(0xFFEF4444); // Red 500
  static const Color successColor = Color(0xFF10B981); // Emerald 500
  static const Color warningColor = Color(0xFFF59E0B); // Amber 500
  
  static const Color backgroundColor = Color(0xFFF8FAFC); // Slate 50
  static const Color surfaceColor = Color(0xFFFFFFFF);
  
  static const Color textPrimary = Color(0xFF0F172A); // Slate 900
  static const Color textSecondary = Color(0xFF64748B); // Slate 500
  static const Color textHint = Color(0xFF94A3B8); // Slate 400

  /// A linear gradient used for primary UI elements like large buttons or headers.
  static const LinearGradient primaryGradient = LinearGradient(
    colors: [Color(0xFF4F46E5), Color(0xFF6366F1)],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );
}

/// The main theme configuration for the Myki Flutter application.
///
/// This class provides the [ThemeData] required by the [MaterialApp] widget,
/// defining the look and feel of widgets like buttons, text fields, and cards.
class AppTheme {
  // Private constructor to prevent instantiation.
  AppTheme._();

  /// Generates the light theme configuration for the application.
  ///
  /// This utilizes Material 3 design principles and customizes them with the
  /// [MykiAppTheme] color palette and [GoogleFonts.inter] typography.
  static ThemeData get lightTheme {
    return ThemeData(
      // Enables Material 3 design system.
      useMaterial3: true,
      brightness: Brightness.light,
      scaffoldBackgroundColor: MykiAppTheme.backgroundColor,
      
      // Defines the core color scheme using a seed color for harmonious generation.
      colorScheme: ColorScheme.fromSeed(
        seedColor: MykiAppTheme.primaryColor,
        brightness: Brightness.light,
        primary: MykiAppTheme.primaryColor,
        secondary: MykiAppTheme.secondaryColor,
        error: MykiAppTheme.errorColor,
        surface: MykiAppTheme.surfaceColor,
      ),

      // Typography configuration using the Inter font family.
      textTheme: GoogleFonts.interTextTheme().copyWith(
        displayLarge: GoogleFonts.inter(
          fontSize: 36,
          fontWeight: FontWeight.w800,
          letterSpacing: -1.0,
          color: MykiAppTheme.textPrimary,
        ),
        displayMedium: GoogleFonts.inter(
          fontSize: 28,
          fontWeight: FontWeight.bold,
          letterSpacing: -0.5,
          color: MykiAppTheme.textPrimary,
        ),
        headlineLarge: GoogleFonts.inter(
          fontSize: 24,
          fontWeight: FontWeight.bold,
          letterSpacing: -0.5,
          color: MykiAppTheme.textPrimary,
        ),
        titleLarge: GoogleFonts.inter(
          fontSize: 18,
          fontWeight: FontWeight.w600,
          color: MykiAppTheme.textPrimary,
        ),
        bodyLarge: GoogleFonts.inter(
          fontSize: 16,
          fontWeight: FontWeight.normal,
          color: MykiAppTheme.textPrimary,
        ),
        bodyMedium: GoogleFonts.inter(
          fontSize: 14,
          fontWeight: FontWeight.normal,
          color: MykiAppTheme.textSecondary,
        ),
      ),

      // Global style for AppBars.
      appBarTheme: AppBarTheme(
        elevation: 0,
        centerTitle: true,
        backgroundColor: MykiAppTheme.surfaceColor,
        foregroundColor: MykiAppTheme.textPrimary,
        surfaceTintColor: Colors.transparent,
        titleTextStyle: GoogleFonts.inter(
          fontSize: 18,
          fontWeight: FontWeight.w600,
          color: MykiAppTheme.textPrimary,
        ),
        iconTheme: const IconThemeData(color: MykiAppTheme.textPrimary),
      ),

      // Global style for ElevatedButtons.
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          elevation: 0,
          backgroundColor: MykiAppTheme.primaryColor,
          foregroundColor: Colors.white,
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
          ),
          textStyle: GoogleFonts.inter(
            fontSize: 16,
            fontWeight: FontWeight.w600,
            letterSpacing: 0.2,
          ),
        ),
      ),

      // Global style for TextButtons.
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(
          foregroundColor: MykiAppTheme.primaryColor,
          textStyle: GoogleFonts.inter(
            fontSize: 16,
            fontWeight: FontWeight.w600,
          ),
        ),
      ),

      // Global style for InputFields (TextFields).
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: MykiAppTheme.surfaceColor,
        hintStyle: GoogleFonts.inter(color: MykiAppTheme.textHint),
        labelStyle: GoogleFonts.inter(color: MykiAppTheme.textSecondary),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(16),
          borderSide: BorderSide(color: Colors.blueGrey.shade200, width: 1),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(16),
          borderSide: BorderSide(color: Colors.blueGrey.shade200, width: 1),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(16),
          borderSide: const BorderSide(color: MykiAppTheme.primaryColor, width: 2),
        ),
        errorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(16),
          borderSide: const BorderSide(color: MykiAppTheme.errorColor, width: 1),
        ),
        contentPadding: const EdgeInsets.symmetric(
          horizontal: 20,
          vertical: 18,
        ),
      ),

      // Global style for Cards.
      cardTheme: CardThemeData(
        elevation: 0,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(20),
          side: BorderSide(color: Colors.blueGrey.shade200, width: 1),
        ),
        color: MykiAppTheme.surfaceColor,
        clipBehavior: Clip.antiAlias,
      ),
    );
  }
}
