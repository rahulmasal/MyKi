// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod vault;
mod crypto;
mod commands;

use tauri::Manager;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// The main entry point for the Myki Extension backend.
///
/// This function initializes logging, sets up the Tauri application builder,
/// registers IPC commands, and ensures the local vault directory is ready.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Initialize logging with tracing-subscriber.
    // By default, it logs 'info' level and above to the console.
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Myki Extension v{}", env!("CARGO_PKG_VERSION"));

    // Build the Tauri application
    tauri::Builder::default()
        // Initialize plugins for common desktop tasks
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        // Register all IPC commands that can be called from the frontend
        .invoke_handler(tauri::generate_handler![
            commands::get_credentials_for_url,
            commands::fill_credential,
            commands::generate_password,
            commands::unlock_vault,
            commands::lock_vault,
            commands::is_vault_unlocked,
            commands::get_vault_status,
            commands::add_credential,
            commands::update_credential,
            commands::delete_credential,
            commands::search_credentials,
        ])
        .setup(|app| {
            // Initialization logic that runs before the app starts.
            // We ensure the application data directory (where the vault DB lives) exists.
            let vault_dir = app.path().app_data_dir().expect("Failed to get app data dir");
            std::fs::create_dir_all(&vault_dir).expect("Failed to create vault directory");
            
            tracing::info!("Vault directory: {:?}", vault_dir);
            
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn main() {
    // Bootstrap the application
    run();
}
