//! Myki CLI - Secure Command Line Interface
//! 
//! Provides technical users with direct access to the Myki vault from the terminal.

use clap::{Parser, Subcommand};
use rpassword::read_password;
use myki_core::{VaultDatabase, derive_key};
use std::path::PathBuf;

/// Secure CLI for Myki Password Manager
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to the vault database
    #[arg(short, long, value_name = "FILE", default_value = "vault.db")]
    vault: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all credentials in the vault
    List,
    /// Search for a specific credential
    Search {
        /// The query string (title or username)
        query: String,
    },
    /// Add a new credential to the vault
    Add {
        /// Display title for the credential
        title: String,
        /// Username for the account
        username: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Check if vault exists
    if !cli.vault.exists() {
        return Err(anyhow::anyhow!("Vault does not exist at {:?}. Use 'create' command first.", cli.vault));
    }

    print!("Enter Master Password: ");
    std::io::Write::flush(&mut std::io::stdout())?;
    let password = read_password()?;

    // Read the salt directly from the unencrypted vault_meta table
    let conn = rusqlite::Connection::open(cli.vault.to_str().unwrap())
        .map_err(|e| anyhow::anyhow!("Failed to open vault database: {}", e))?;
    
    let salt_b64: String = conn.query_row(
        "SELECT value FROM vault_meta WHERE key = 'salt'",
        [],
        |row| row.get(0),
    ).map_err(|e| anyhow::anyhow!("Failed to get salt from vault: {}. Is the password correct?", e))?;
    
    drop(conn);
    
    use base64::Engine;
    let salt_vec = base64::engine::general_purpose::STANDARD
        .decode(salt_b64.as_bytes())
        .map_err(|e| anyhow::anyhow!("Invalid salt encoding: {}", e))?;
    
    if salt_vec.len() != 32 {
        return Err(anyhow::anyhow!("Invalid salt length: expected 32 bytes, got {}", salt_vec.len()));
    }
    
    let mut salt_arr = [0u8; 32];
    salt_arr.copy_from_slice(&salt_vec);
    
    let master_key = derive_key(&password, &salt_arr, &Default::default())
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let db = VaultDatabase::open(cli.vault.to_str().unwrap(), &master_key)
        .map_err(|e| anyhow::anyhow!("Failed to open vault: {}. Is the password correct?", e))?;

    match &cli.command {
        Commands::List => {
            let creds = db.get_all_credentials().map_err(|e| anyhow::anyhow!(e.to_string()))?;
            
            println!("{:<20} {:<20} {:<20}", "Title", "Username", "URL");
            println!("{}", "-".repeat(60));
            for c in creds {
                println!("{:<20} {:<20} {:<20}", c.title, c.username, c.url.unwrap_or_default());
            }
        }
        Commands::Search { query } => {
            let creds = db.search_credentials(query).map_err(|e| anyhow::anyhow!(e.to_string()))?;
            
            for c in creds {
                println!("--- {} ---", c.title);
                println!("User: {}", c.username);
                println!("Pass: {}", c.password);
                if let Some(u) = c.url { println!("URL:  {}", u); }
            }
        }
        Commands::Add { title, username } => {
            print!("Enter password for {}: ", title);
            std::io::Write::flush(&mut std::io::stdout())?;
            let cred_password = read_password()?;
            
            let cred = myki_core::Credential::new(title.clone(), username.clone(), cred_password);
            db.save_credential(&cred).map_err(|e| anyhow::anyhow!(e.to_string()))?;
            
            println!("Successfully added {} to vault.", title);
        }
    }

    Ok(())
}
