# Myki CLI - Command Line Interface

<p align="center">
  <img src="https://img.shields.io/badge/Rust-1.70+-orange.svg?style=flat-square&logo=rust" alt="Rust"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue.svg?style=flat-square" alt="Platforms"/>
</p>

---

## 📖 Overview

**myki_cli** provides a terminal-based interface to the Myki vault for power users and developers.

### Features

- **🔐 Secure**: Master password never stored, derived key held in memory only
- **📋 List Credentials**: View all stored credentials
- **🔍 Search**: Find credentials by title or username
- **➕ Add Credentials**: Add new entries from the command line
- **🧩 Unix Philosophy**: Composable with other command-line tools

---

## 🚀 Quick Start

### Installation

```bash
# Build from source
cargo build --release

# The binary will be at target/release/myki_cli (or myki_cli.exe on Windows)
```

### Basic Usage

```bash
# List all credentials
myki_cli list

# Search for a credential
myki_cli search "github"

# Add a new credential
myki_cli add "GitHub" "user@example.com"

# Use custom vault path
myki_cli --vault /path/to/vault.db list
```

---

## 📚 Command Reference

### `list`

Lists all credentials in the vault.

```bash
myki_cli list
```

**Output:**

```
Title                Username           URL
------------------------------------------------------------
GitHub               user@email.com     https://github.com
Google               john@gmail.com     https://google.com
Twitter              @johndoe          https://twitter.com
```

### `search`

Searches for credentials matching the query.

```bash
myki_cli search "github"
```

**Output:**

```
--- GitHub ---
User: user@email.com
Pass: secretpassword123
URL:  https://github.com
```

### `add`

Adds a new credential to the vault.

```bash
myki_cli add "GitHub" "user@email.com"
```

**Interactive Prompts:**

- Master password (for vault access)
- Credential password (for the new entry)

---

## 🔒 Security Model

### Memory Safety

1. **No Password Storage**: Master password is read once, used for key derivation, then discarded
2. **In-Memory Key**: Derived key exists only in memory during operation
3. **No Swap**: Sensitive data is never written to disk swap
4. **Clean Exit**: Memory is properly freed on program exit

### Key Derivation

```
Master Password + Vault Salt ──► Argon2id ──► Vault Key
```

The same Argon2id algorithm used by the mobile app ensures compatibility.

---

## 🏗️ Architecture

```rust
// Entry point
main.rs

// Key operations
├── derive_key()       // Argon2id from myki_core
├── open_vault()      // Decrypt and open database
└── handle_command()  // Route to command handlers
```

### Data Flow

```
User Input (CLI)
       │
       ▼
┌──────────────────┐
│   Parse Args     │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Read Salt (SQLite)│
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Derive Key      │  ◄── Password entered via terminal
│  (Argon2id)      │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Open Vault DB    │  ◄── Encrypted SQLite
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Execute Command  │  ◄── list/search/add
└────────┬─────────┘
         │
         ▼
      Output
```

---

## 📦 Dependencies

| Crate       | Purpose                             |
| ----------- | ----------------------------------- |
| `clap`      | Command-line argument parsing       |
| `rpassword` | Secure password input from terminal |
| `rusqlite`  | SQLite database access              |
| `anyhow`    | Error handling                      |
| `myki_core` | Cryptographic operations            |

---

## 🔧 Configuration

### Vault Location

Default: `vault.db` in current directory

Override with `--vault` / `-v` flag:

```bash
myki_cli --vault /secure/vault.db list
```

---

## 🐛 Troubleshooting

### "Vault does not exist"

The vault file hasn't been created yet. Use the mobile app to create your first vault.

### "Failed to get salt from vault"

Either:

- Wrong master password
- Corrupted vault file
- Vault file is not a valid Myki vault

### "Invalid salt length"

The vault file may be corrupted or from a different version.

---

## 📖 See Also

- [Myki Core](../myki_core/) - Rust cryptographic library
- [Myki App](../myki_app/) - Mobile application
- [Main README](../README.md) - Project overview
