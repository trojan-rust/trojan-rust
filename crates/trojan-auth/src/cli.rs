//! CLI module for trojan-auth.
//!
//! This module provides the command-line interface for managing SQL authentication
//! users. It can be used either as a standalone binary or as a subcommand of the
//! main trojan-rs CLI.
//!
//! # Usage
//!
//! ```bash
//! # Add a user
//! trojan-auth add -d sqlite:users.db -p mypassword -u user1
//!
//! # List all users
//! trojan-auth list -d sqlite:users.db
//!
//! # Update user settings
//! trojan-auth update -d sqlite:users.db -u user1 --traffic-limit 10GB
//!
//! # Remove a user
//! trojan-auth remove -d sqlite:users.db -u user1
//!
//! # Initialize database schema
//! trojan-auth init -d sqlite:users.db
//! ```

use clap::{Parser, Subcommand};
use tabled::{Table, Tabled};

use crate::sha224_hex;

/// Trojan authentication management CLI arguments.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "trojan-auth",
    version,
    about = "Manage trojan authentication users"
)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub command: AuthCommands,
}

/// Auth CLI subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum AuthCommands {
    /// Initialize database schema.
    Init {
        /// Database connection URL.
        #[arg(short, long, env = "DATABASE_URL")]
        database: String,
    },

    /// Add a new user.
    Add {
        /// Database connection URL.
        #[arg(short, long, env = "DATABASE_URL")]
        database: String,

        /// User password.
        #[arg(short, long)]
        password: String,

        /// User ID (optional identifier for logging).
        #[arg(short, long)]
        user_id: Option<String>,

        /// Traffic limit (e.g., "10GB", "500MB", "0" for unlimited).
        #[arg(short, long, default_value = "0")]
        traffic_limit: String,

        /// Expiration date (e.g., "2024-12-31", "30d" for 30 days, "0" for never).
        #[arg(short, long, default_value = "0")]
        expires: String,
    },

    /// Remove a user.
    Remove {
        /// Database connection URL.
        #[arg(short, long, env = "DATABASE_URL")]
        database: String,

        /// User ID to remove.
        #[arg(short, long, group = "target")]
        user_id: Option<String>,

        /// Password hash to remove.
        #[arg(long, group = "target")]
        hash: Option<String>,

        /// Password to remove (will be hashed).
        #[arg(short, long, group = "target")]
        password: Option<String>,
    },

    /// List all users.
    List {
        /// Database connection URL.
        #[arg(short, long, env = "DATABASE_URL")]
        database: String,

        /// Output format (table, json, csv).
        #[arg(short, long, default_value = "table")]
        format: String,
    },

    /// Update user settings.
    Update {
        /// Database connection URL.
        #[arg(short, long, env = "DATABASE_URL")]
        database: String,

        /// User ID to update.
        #[arg(short, long)]
        user_id: String,

        /// New traffic limit (e.g., "10GB", "500MB").
        #[arg(short, long)]
        traffic_limit: Option<String>,

        /// New expiration date.
        #[arg(short, long)]
        expires: Option<String>,

        /// Enable the user.
        #[arg(long)]
        enable: bool,

        /// Disable the user.
        #[arg(long)]
        disable: bool,
    },

    /// Reset traffic usage for a user.
    ResetTraffic {
        /// Database connection URL.
        #[arg(short, long, env = "DATABASE_URL")]
        database: String,

        /// User ID to reset (or "all" for all users).
        #[arg(short, long)]
        user_id: String,
    },

    /// Show password hash (for manual configuration).
    Hash {
        /// Password to hash.
        password: String,
    },
}

/// User row for display.
#[derive(Tabled)]
struct UserDisplay {
    #[tabled(rename = "ID")]
    id: i64,
    #[tabled(rename = "User ID")]
    user_id: String,
    #[tabled(rename = "Traffic Limit")]
    traffic_limit: String,
    #[tabled(rename = "Traffic Used")]
    traffic_used: String,
    #[tabled(rename = "Expires")]
    expires_at: String,
    #[tabled(rename = "Enabled")]
    enabled: String,
}

/// Run the auth CLI with the given arguments.
///
/// This is the main entry point for the auth CLI, used by both the
/// standalone binary and the unified trojan-rs CLI.
pub async fn run(args: AuthArgs) -> Result<(), Box<dyn std::error::Error>> {
    match args.command {
        AuthCommands::Init { database } => init_database(&database).await,
        AuthCommands::Add {
            database,
            password,
            user_id,
            traffic_limit,
            expires,
        } => {
            add_user(
                &database,
                &password,
                user_id.as_deref(),
                &traffic_limit,
                &expires,
            )
            .await
        }
        AuthCommands::Remove {
            database,
            user_id,
            hash,
            password,
        } => {
            remove_user(
                &database,
                user_id.as_deref(),
                hash.as_deref(),
                password.as_deref(),
            )
            .await
        }
        AuthCommands::List { database, format } => list_users(&database, &format).await,
        AuthCommands::Update {
            database,
            user_id,
            traffic_limit,
            expires,
            enable,
            disable,
        } => {
            update_user(
                &database,
                &user_id,
                traffic_limit.as_deref(),
                expires.as_deref(),
                enable,
                disable,
            )
            .await
        }
        AuthCommands::ResetTraffic { database, user_id } => {
            reset_traffic(&database, &user_id).await
        }
        AuthCommands::Hash { password } => {
            println!("{}", sha224_hex(&password));
            Ok(())
        }
    }
}

/// Connect to database.
async fn connect(url: &str) -> Result<sqlx::AnyPool, Box<dyn std::error::Error>> {
    sqlx::any::install_default_drivers();
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await?;
    Ok(pool)
}

/// Detect database type from URL.
fn is_postgres(url: &str) -> bool {
    url.starts_with("postgres://") || url.starts_with("postgresql://")
}

/// Initialize database schema.
async fn init_database(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let pool = connect(url).await?;

    let schema = if is_postgres(url) {
        r#"
        CREATE TABLE IF NOT EXISTS trojan_users (
            id SERIAL PRIMARY KEY,
            password_hash VARCHAR(56) NOT NULL UNIQUE,
            user_id VARCHAR(255),
            traffic_limit BIGINT NOT NULL DEFAULT 0,
            traffic_used BIGINT NOT NULL DEFAULT 0,
            expires_at BIGINT NOT NULL DEFAULT 0,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_trojan_users_hash ON trojan_users(password_hash);
        CREATE INDEX IF NOT EXISTS idx_trojan_users_user_id ON trojan_users(user_id);
        "#
    } else {
        r#"
        CREATE TABLE IF NOT EXISTS trojan_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_hash TEXT NOT NULL UNIQUE,
            user_id TEXT,
            traffic_limit INTEGER NOT NULL DEFAULT 0,
            traffic_used INTEGER NOT NULL DEFAULT 0,
            expires_at INTEGER NOT NULL DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_trojan_users_hash ON trojan_users(password_hash);
        CREATE INDEX IF NOT EXISTS idx_trojan_users_user_id ON trojan_users(user_id);
        "#
    };

    // Execute each statement separately
    for stmt in schema.split(';').filter(|s| !s.trim().is_empty()) {
        sqlx::query(stmt).execute(&pool).await?;
    }

    println!("Database schema initialized successfully.");
    Ok(())
}

/// Parse traffic size string (e.g., "10GB", "500MB") to bytes.
#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
fn parse_traffic(s: &str) -> Result<i64, Box<dyn std::error::Error>> {
    let s = s.trim().to_uppercase();
    if s == "0" || s.is_empty() {
        return Ok(0);
    }

    let (num, unit) = if s.ends_with("TB") {
        (&s[..s.len() - 2], 1024i64 * 1024 * 1024 * 1024)
    } else if s.ends_with("GB") {
        (&s[..s.len() - 2], 1024i64 * 1024 * 1024)
    } else if s.ends_with("MB") {
        (&s[..s.len() - 2], 1024i64 * 1024)
    } else if s.ends_with("KB") {
        (&s[..s.len() - 2], 1024i64)
    } else if s.ends_with('B') {
        (&s[..s.len() - 1], 1i64)
    } else {
        // Assume bytes if no unit
        (s.as_str(), 1i64)
    };

    let value: f64 = num.trim().parse()?;
    Ok((value * unit as f64) as i64)
}

/// Parse expiration string to unix timestamp.
#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
fn parse_expires(s: &str) -> Result<i64, Box<dyn std::error::Error>> {
    let s = s.trim();
    if s == "0" || s.is_empty() {
        return Ok(0);
    }

    // Check for relative duration (e.g., "30d", "1y")
    if s.ends_with('d') || s.ends_with('D') {
        let days: i64 = s[..s.len() - 1].parse()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        return Ok(now + days * 24 * 60 * 60);
    }

    if s.ends_with('m') || s.ends_with('M') {
        let months: i64 = s[..s.len() - 1].parse()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        return Ok(now + months * 30 * 24 * 60 * 60);
    }

    if s.ends_with('y') || s.ends_with('Y') {
        let years: i64 = s[..s.len() - 1].parse()?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        return Ok(now + years * 365 * 24 * 60 * 60);
    }

    // Try parsing as date (YYYY-MM-DD)
    if let Ok(date) = chrono_parse_date(s) {
        return Ok(date);
    }

    // Try parsing as unix timestamp
    if let Ok(ts) = s.parse::<i64>() {
        return Ok(ts);
    }

    Err(format!("Invalid expiration format: {}", s).into())
}

/// Simple date parsing (YYYY-MM-DD) without chrono dependency.
#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
fn chrono_parse_date(s: &str) -> Result<i64, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return Err("Invalid date format".into());
    }

    let year: i32 = parts[0].parse()?;
    let month: u32 = parts[1].parse()?;
    let day: u32 = parts[2].parse()?;

    // Simple calculation (not accounting for leap years perfectly)
    let days_since_epoch = (year - 1970) as i64 * 365
        + (year - 1969) as i64 / 4 // leap years
        + days_in_year_before_month(month)
        + day as i64
        - 1;

    Ok(days_since_epoch * 24 * 60 * 60)
}

fn days_in_year_before_month(month: u32) -> i64 {
    match month {
        1 => 0,
        2 => 31,
        3 => 59,
        4 => 90,
        5 => 120,
        6 => 151,
        7 => 181,
        8 => 212,
        9 => 243,
        10 => 273,
        11 => 304,
        12 => 334,
        _ => 0,
    }
}

/// Format bytes to human readable string.
fn format_bytes(bytes: i64) -> String {
    const KB: i64 = 1024;
    const MB: i64 = KB * 1024;
    const GB: i64 = MB * 1024;
    const TB: i64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format traffic limit (0 means unlimited).
fn format_traffic_limit(bytes: i64) -> String {
    if bytes == 0 {
        "Unlimited".to_string()
    } else {
        format_bytes(bytes)
    }
}

/// Format unix timestamp to human readable string.
fn format_expires(ts: i64) -> String {
    if ts == 0 {
        return "Never".to_string();
    }

    // Simple formatting
    let secs_per_day = 24 * 60 * 60;
    let days_since_epoch = ts / secs_per_day;
    let years = 1970 + days_since_epoch / 365;
    let remaining_days = days_since_epoch % 365;
    let month = remaining_days / 30 + 1;
    let day = remaining_days % 30 + 1;

    format!("{:04}-{:02}-{:02}", years, month.min(12), day.min(31))
}

/// Add a new user.
async fn add_user(
    url: &str,
    password: &str,
    user_id: Option<&str>,
    traffic_limit: &str,
    expires: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let pool = connect(url).await?;
    let hash = sha224_hex(password);
    let traffic = parse_traffic(traffic_limit)?;
    let expires_at = parse_expires(expires)?;

    let query = if is_postgres(url) {
        "INSERT INTO trojan_users (password_hash, user_id, traffic_limit, expires_at) VALUES ($1, $2, $3, $4)"
    } else {
        "INSERT INTO trojan_users (password_hash, user_id, traffic_limit, expires_at) VALUES (?, ?, ?, ?)"
    };

    sqlx::query(query)
        .bind(&hash)
        .bind(user_id)
        .bind(traffic)
        .bind(expires_at)
        .execute(&pool)
        .await?;

    println!("User added successfully.");
    println!("  Password hash: {}", hash);
    if let Some(id) = user_id {
        println!("  User ID: {}", id);
    }
    println!("  Traffic limit: {}", format_traffic_limit(traffic));
    println!("  Expires: {}", format_expires(expires_at));

    Ok(())
}

/// Remove a user.
async fn remove_user(
    url: &str,
    user_id: Option<&str>,
    hash: Option<&str>,
    password: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let pool = connect(url).await?;

    let (query, bind_value) = if let Some(uid) = user_id {
        let q = if is_postgres(url) {
            "DELETE FROM trojan_users WHERE user_id = $1"
        } else {
            "DELETE FROM trojan_users WHERE user_id = ?"
        };
        (q, uid.to_string())
    } else if let Some(h) = hash {
        let q = if is_postgres(url) {
            "DELETE FROM trojan_users WHERE password_hash = $1"
        } else {
            "DELETE FROM trojan_users WHERE password_hash = ?"
        };
        (q, h.to_string())
    } else if let Some(p) = password {
        let q = if is_postgres(url) {
            "DELETE FROM trojan_users WHERE password_hash = $1"
        } else {
            "DELETE FROM trojan_users WHERE password_hash = ?"
        };
        (q, sha224_hex(p))
    } else {
        return Err("Must specify --user-id, --hash, or --password".into());
    };

    let result = sqlx::query(query).bind(&bind_value).execute(&pool).await?;

    if result.rows_affected() > 0 {
        println!("User removed successfully.");
    } else {
        println!("No user found matching the criteria.");
    }

    Ok(())
}

/// List all users.
async fn list_users(url: &str, format: &str) -> Result<(), Box<dyn std::error::Error>> {
    let pool = connect(url).await?;

    let query = "SELECT id, password_hash, user_id, traffic_limit, traffic_used, expires_at, enabled FROM trojan_users ORDER BY id";
    let rows = sqlx::query(query).fetch_all(&pool).await?;

    if rows.is_empty() {
        println!("No users found.");
        return Ok(());
    }

    let users: Vec<UserDisplay> = rows
        .iter()
        .map(|row| {
            use sqlx::Row;
            let id: i64 = row.try_get("id").unwrap_or(0);
            let user_id: Option<String> = row.try_get("user_id").ok();
            let traffic_limit: i64 = row.try_get("traffic_limit").unwrap_or(0);
            let traffic_used: i64 = row.try_get("traffic_used").unwrap_or(0);
            let expires_at: i64 = row.try_get("expires_at").unwrap_or(0);
            let enabled: bool = row
                .try_get::<bool, _>("enabled")
                .or_else(|_| row.try_get::<i32, _>("enabled").map(|v| v != 0))
                .unwrap_or(true);

            UserDisplay {
                id,
                user_id: user_id.unwrap_or_else(|| "-".to_string()),
                traffic_limit: format_traffic_limit(traffic_limit),
                traffic_used: format_bytes(traffic_used),
                expires_at: format_expires(expires_at),
                enabled: if enabled { "Yes" } else { "No" }.to_string(),
            }
        })
        .collect();

    match format {
        "json" => {
            // Simple JSON output
            println!("[");
            for (i, user) in users.iter().enumerate() {
                let comma = if i < users.len() - 1 { "," } else { "" };
                println!(
                    r#"  {{"id": {}, "user_id": "{}", "traffic_limit": "{}", "traffic_used": "{}", "expires_at": "{}", "enabled": "{}"}}{}"#,
                    user.id,
                    user.user_id,
                    user.traffic_limit,
                    user.traffic_used,
                    user.expires_at,
                    user.enabled,
                    comma
                );
            }
            println!("]");
        }
        "csv" => {
            println!("id,user_id,traffic_limit,traffic_used,expires_at,enabled");
            for user in users {
                println!(
                    "{},{},{},{},{},{}",
                    user.id,
                    user.user_id,
                    user.traffic_limit,
                    user.traffic_used,
                    user.expires_at,
                    user.enabled
                );
            }
        }
        _ => {
            // Table format (default)
            let table = Table::new(users).to_string();
            println!("{}", table);
        }
    }

    Ok(())
}

/// Update user settings.
async fn update_user(
    url: &str,
    user_id: &str,
    traffic_limit: Option<&str>,
    expires: Option<&str>,
    enable: bool,
    disable: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let pool = connect(url).await?;

    let mut updates = Vec::new();
    let mut values: Vec<String> = Vec::new();

    if let Some(tl) = traffic_limit {
        let traffic = parse_traffic(tl)?;
        updates.push("traffic_limit");
        values.push(traffic.to_string());
    }

    if let Some(exp) = expires {
        let expires_at = parse_expires(exp)?;
        updates.push("expires_at");
        values.push(expires_at.to_string());
    }

    if enable {
        updates.push("enabled");
        values.push("1".to_string());
    } else if disable {
        updates.push("enabled");
        values.push("0".to_string());
    }

    if updates.is_empty() {
        println!("No updates specified.");
        return Ok(());
    }

    // Build query dynamically
    let set_clause: String = if is_postgres(url) {
        updates
            .iter()
            .enumerate()
            .map(|(i, col)| format!("{} = ${}", col, i + 1))
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        updates
            .iter()
            .map(|col| format!("{} = ?", col))
            .collect::<Vec<_>>()
            .join(", ")
    };

    let where_clause = if is_postgres(url) {
        format!("user_id = ${}", updates.len() + 1)
    } else {
        "user_id = ?".to_string()
    };

    let query = format!(
        "UPDATE trojan_users SET {} WHERE {}",
        set_clause, where_clause
    );

    let mut q = sqlx::query(&query);
    for v in &values {
        q = q.bind(v);
    }
    q = q.bind(user_id);

    let result = q.execute(&pool).await?;

    if result.rows_affected() > 0 {
        println!("User updated successfully.");
    } else {
        println!("No user found with user_id: {}", user_id);
    }

    Ok(())
}

/// Reset traffic usage.
async fn reset_traffic(url: &str, user_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let pool = connect(url).await?;

    let (query, affected) = if user_id == "all" {
        let q = "UPDATE trojan_users SET traffic_used = 0";
        let result = sqlx::query(q).execute(&pool).await?;
        (q, result.rows_affected())
    } else {
        let q = if is_postgres(url) {
            "UPDATE trojan_users SET traffic_used = 0 WHERE user_id = $1"
        } else {
            "UPDATE trojan_users SET traffic_used = 0 WHERE user_id = ?"
        };
        let result = sqlx::query(q).bind(user_id).execute(&pool).await?;
        (q, result.rows_affected())
    };

    if affected > 0 {
        println!(
            "Traffic reset for {} user(s).",
            if user_id == "all" {
                format!("{}", affected)
            } else {
                "1".to_string()
            }
        );
    } else {
        println!("No user found matching the criteria.");
    }

    let _ = query; // Suppress unused warning
    Ok(())
}
