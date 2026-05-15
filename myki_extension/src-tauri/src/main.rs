// Windows Desktop Application Entry Point
// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

use tauri::Manager;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use commands::AppState;
use std::panic;

fn main() {
    // 1. Determine log directory early
    let identifier = "com.myki.extension";
    let log_dir = dirs::data_dir()
        .map(|d| d.join(identifier).join("logs"))
        .unwrap_or_else(|| std::env::current_dir().unwrap().join("logs"));
    
    if let Err(e) = std::fs::create_dir_all(&log_dir) {
        // If we can't even create logs, we're in trouble, but let's try to continue
        eprintln!("Failed to create log directory: {}", e);
    }

    // 2. Initialize file logging
    let file_appender = tracing_appender::rolling::daily(&log_dir, "myki.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(non_blocking))
        .with(tracing_subscriber::fmt::layer()) // Also log to stdout if available
        .init();

    // 3. Set up panic hook to capture crashes
    panic::set_hook(Box::new(|panic_info| {
        let location = panic_info.location().map(|l| format!("at {}:{}:{}", l.file(), l.line(), l.column())).unwrap_or_else(|| "unknown location".to_string());
        let payload = panic_info.payload();
        let message = if let Some(s) = payload.downcast_ref::<&str>() {
            *s
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.as_str()
        } else {
            "no message"
        };
        
        tracing::error!("APPLICATION PANIC: {} {}", message, location);
    }));

    tracing::info!("Starting Myki Desktop v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Log directory: {:?}", log_dir);

    // 4. Start Tauri
    tauri::Builder::default()
        .manage(AppState::default())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .invoke_handler(tauri::generate_handler![
            commands::generate_password,
            commands::unlock_vault,
            commands::lock_vault,
            commands::is_vault_unlocked,
            commands::vault_exists,
            commands::add_credential,
            commands::delete_credential,
            commands::search_credentials,
            commands::get_all_credentials,
            commands::get_credential_password,
            commands::create_vault,
            commands::setup_desktop,
            commands::get_vault_path,
        ])
        .setup(|app| {
            // Initialize vault on startup
            let vault_dir = app.path().app_data_dir()
                .map_err(|e| {
                    tracing::error!("Failed to get app data dir: {}", e);
                    e
                })?;
            
            if let Err(e) = std::fs::create_dir_all(&vault_dir) {
                tracing::error!("Failed to create vault directory {:?}: {}", vault_dir, e);
                return Err(e.into());
            }
            
            tracing::info!("Vault directory initialized: {:?}", vault_dir);
            
            Ok(())
        })
        .run(tauri::generate_context!())
        .map_err(|e| {
            tracing::error!("Tauri runtime error: {}", e);
            e
        })
        .expect("error while running tauri application");
}
