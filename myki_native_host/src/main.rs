use myki_core::{VaultDatabase, CredentialMeta, derive_key};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::path::PathBuf;

#[derive(Deserialize)]
struct Request {
    command: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    vault: String,
}

#[derive(Serialize)]
struct Response {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

struct App {
    vault_path: PathBuf,
    db: Option<VaultDatabase>,
}

fn read_message() -> Result<Request, String> {
    let mut len_buf = [0u8; 4];
    io::stdin().read_exact(&mut len_buf).map_err(|e| format!("Failed to read length: {}", e))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    io::stdin().read_exact(&mut buf).map_err(|e| format!("Failed to read message: {}", e))?;
    serde_json::from_slice(&buf).map_err(|e| format!("Invalid JSON: {}", e))
}

fn write_message(response: &Response) {
    let json = serde_json::to_string(response).unwrap();
    let len = json.len() as u32;
    let len_buf = len.to_le_bytes();
    let mut stdout = io::stdout();
    let _ = stdout.write_all(&len_buf);
    let _ = stdout.write_all(json.as_bytes());
    let _ = stdout.flush();
}

fn main() {
    let vault_path = if cfg!(target_os = "windows") {
        PathBuf::from(std::env::var("APPDATA").unwrap_or_default())
            .join("com.myki.extension")
            .join("vault.db")
    } else {
        dirs_data().join("com.myki.extension").join("vault.db")
    };

    let mut app = App { vault_path, db: None };

    loop {
        let req = match read_message() {
            Ok(r) => r,
            Err(e) => {
                write_message(&Response { success: false, data: None, error: Some(e) });
                continue;
            }
        };

        let response = match req.command.as_str() {
            "unlock" => cmd_unlock(&mut app, &req),
            "lock" => cmd_lock(&mut app),
            "list" => cmd_list(&app),
            "search" => cmd_search(&app, &req),
            "get_password" => cmd_get_password(&app, &req),
            "generate_password" => cmd_generate_password(&req),
            "ping" => Response { success: true, data: Some(serde_json::json!("pong")), error: None },
            _ => Response { success: false, data: None, error: Some(format!("Unknown command: {}", req.command)) },
        };

        write_message(&response);
    }
}

fn cmd_unlock(app: &mut App, req: &Request) -> Response {
    let vault = if req.vault.is_empty() { app.vault_path.clone() } else { PathBuf::from(&req.vault) };
    if !vault.exists() {
        return Response { success: false, data: None, error: Some("Vault not found".into()) };
    }

    let vault_str = vault.to_string_lossy().to_string();
    let conn = match rusqlite::Connection::open(&vault_str) {
        Ok(c) => c,
        Err(e) => return Response { success: false, data: None, error: Some(format!("DB error: {}", e)) },
    };

    let salt_b64: String = match conn.query_row(
        "SELECT value FROM vault_meta WHERE key = 'salt'", [], |row| row.get(0)
    ) {
        Ok(s) => s,
        Err(_) => return Response { success: false, data: None, error: Some("Corrupted vault".into()) },
    };

    let salt_bytes = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, salt_b64.as_bytes()) {
        Ok(b) => b,
        Err(_) => return Response { success: false, data: None, error: Some("Invalid salt".into()) },
    };

    if salt_bytes.len() != 32 {
        return Response { success: false, data: None, error: Some("Invalid salt length".into()) };
    }

    let mut salt_arr = [0u8; 32];
    salt_arr.copy_from_slice(&salt_bytes);

    let master_key = match derive_key(&req.password, &salt_arr, &Default::default()) {
        Ok(k) => k,
        Err(e) => return Response { success: false, data: None, error: Some(format!("Key derivation failed: {}", e)) },
    };

    let db = match VaultDatabase::open(&vault_str, &master_key) {
        Ok(d) => d,
        Err(e) => return Response { success: false, data: None, error: Some(format!("Wrong password: {}", e)) },
    };

    app.db = Some(db);
    app.vault_path = vault;
    Response { success: true, data: Some(serde_json::json!({"status": "unlocked"})), error: None }
}

fn cmd_lock(app: &mut App) -> Response {
    app.db = None;
    Response { success: true, data: Some(serde_json::json!({"status": "locked"})), error: None }
}

fn cmd_list(app: &App) -> Response {
    let db = match &app.db {
        Some(d) => d,
        None => return Response { success: false, data: None, error: Some("Vault is locked".into()) },
    };
    match db.get_all_credential_metas() {
        Ok(metas) => {
            let items: Vec<serde_json::Value> = metas.iter().map(|c| serde_json::json!({
                "id": c.id, "title": c.title, "username": c.username,
                "url": c.url, "favorite": c.favorite,
            })).collect();
            Response { success: true, data: Some(serde_json::json!(items)), error: None }
        }
        Err(e) => Response { success: false, data: None, error: Some(format!("Failed to list: {}", e)) },
    }
}

fn cmd_search(app: &App, req: &Request) -> Response {
    let db = match &app.db {
        Some(d) => d,
        None => return Response { success: false, data: None, error: Some("Vault is locked".into()) },
    };
    match db.search_credential_metas(&req.query) {
        Ok(metas) => {
            let items: Vec<serde_json::Value> = metas.iter().map(|c| serde_json::json!({
                "id": c.id, "title": c.title, "username": c.username,
                "url": c.url, "favorite": c.favorite,
            })).collect();
            Response { success: true, data: Some(serde_json::json!(items)), error: None }
        }
        Err(e) => Response { success: false, data: None, error: Some(format!("Search failed: {}", e)) },
    }
}

fn cmd_get_password(app: &App, req: &Request) -> Response {
    let db = match &app.db {
        Some(d) => d,
        None => return Response { success: false, data: None, error: Some("Vault is locked".into()) },
    };
    if req.id.is_empty() {
        return Response { success: false, data: None, error: Some("Missing credential id".into()) };
    }
    match db.get_credential_password(&req.id) {
        Ok(password) => Response {
            success: true,
            data: Some(serde_json::json!({ "password": password })),
            error: None,
        },
        Err(e) => Response { success: false, data: None, error: Some(format!("{}", e)) },
    }
}

fn cmd_generate_password(_req: &Request) -> Response {
    use rand::Rng;
    let charset: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
    let mut rng = rand::thread_rng();
    let pwd: String = (0..20)
        .map(|_| charset[rng.gen_range(0..charset.len())] as char)
        .collect();
    Response { success: true, data: Some(serde_json::json!({"password": pwd})), error: None }
}

fn dirs_data() -> PathBuf {
    if cfg!(target_os = "windows") {
        PathBuf::from(std::env::var("APPDATA").unwrap_or_default())
    } else if cfg!(target_os = "macos") {
        PathBuf::from(std::env::var("HOME").unwrap_or_default()).join("Library").join("Application Support")
    } else {
        PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".local").join("share")
    }
}
