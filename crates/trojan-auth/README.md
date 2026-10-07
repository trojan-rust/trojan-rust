# trojan-auth

Authentication backends for trojan-rs with support for in-memory passwords and SQL databases.

## Overview

This crate provides pluggable authentication for the Trojan protocol:

- **Memory backend** — Fast in-memory hash set, suitable for static password lists
- **SQL backend** — PostgreSQL, MySQL, and SQLite via sqlx, with traffic accounting and user management CLI
- **Reloadable auth** — Hot-reload passwords on SIGHUP without restarting the server

Batched traffic recording bounds the update queue and each batch with `batch_max_pending` (default: 1000). Each recorder flushes one batch at a time. Recording waits when the queue is full and returns an error after shutdown. Pending traffic includes queued bytes. Call `shutdown().await` before dropping the backend to drain accepted updates.

With caching and `tokio-runtime` enabled, cold requests for the same password hash wait for the first lookup and recheck the cache. Different hashes remain concurrent. Cancellation releases the query lock. Backend errors remain uncached.

The HTTP backend runs at most 16 traffic requests per batch, with a separate batch for relay-hop credits. Each HTTP request has a 10-second deadline. Failed writes are logged and are not retried because traffic increments are not idempotent.

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
