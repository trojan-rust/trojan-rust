# trojan-auth

Authentication backends for trojan-rs with support for in-memory passwords and SQL databases.

## Overview

This crate provides pluggable authentication for the Trojan protocol:

- **Memory backend** — Fast in-memory hash set, suitable for static password lists
- **SQL backend** — PostgreSQL, MySQL, and SQLite via sqlx, with traffic accounting and user management CLI
- **Reloadable auth** — Hot-reload passwords on SIGHUP without restarting the server

## Usage

```rust
use trojan_auth::{AuthBackend, MemoryAuth, sha224_hex};

// Create backend from plaintext passwords
let auth = MemoryAuth::from_passwords(["password1", "password2"]);

// Verify a connection
let hash = sha224_hex("password1");
let result = auth.verify(&hash).await?;
println!("User ID: {}", result.user_id);
```

### SQL Backend

```bash
# Initialize database schema
trojan auth init --database sqlite://users.db

# Add a user with traffic limits
trojan auth add --database sqlite://users.db \
  --password "user-password" \
  --upload-limit 10737418240 \
  --download-limit 107374182400

# List all users
trojan auth list --database sqlite://users.db
```

## Features

| Feature | Description |
|---------|-------------|
| `sql-sqlite` | SQLite authentication backend |
| `sql-postgres` | PostgreSQL authentication backend |
| `sql-mysql` | MySQL authentication backend |
| `cli` | User management CLI subcommand |

## License

GPL-3.0-only
