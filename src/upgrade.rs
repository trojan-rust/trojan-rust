//! Self-upgrade functionality via GitHub releases.

use std::env::consts::{ARCH, OS};
use std::io::{self, Write};
use std::path::PathBuf;

use clap::Args;
use flate2::read::GzDecoder;
use futures_util::StreamExt;
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tar::Archive;
use tokio::io::AsyncWriteExt;

const GITHUB_API: &str = "https://api.github.com/repos/trojan-rust/trojan-rust/releases/latest";
const USER_AGENT: &str = concat!("trojan/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(Debug, Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

/// Upgrade trojan binaries from GitHub releases.
#[derive(Args, Debug)]
pub struct UpgradeArgs {
    /// Check for updates without installing.
    #[arg(long, short = 'c')]
    check: bool,

    /// Force upgrade even if already on latest version.
    #[arg(long, short = 'f')]
    force: bool,

    /// Specify target version to install (e.g., v0.1.0).
    #[arg(long, short = 't', value_name = "VERSION")]
    target: Option<String>,

    /// Skip checksum verification.
    #[arg(long)]
    no_verify: bool,

    /// Binary name to upgrade (default: "trojan").
    #[arg(long, short = 'b')]
    binary: Option<String>,
}

/// Get the target triple for the current platform.
fn get_target_triple() -> Result<&'static str, String> {
    match (OS, ARCH) {
        ("linux", "x86_64") => {
            // Detect musl vs glibc
            if is_musl() {
                Ok("x86_64-unknown-linux-musl")
            } else {
                Ok("x86_64-unknown-linux-gnu")
            }
        }
        ("linux", "aarch64") => {
            if is_musl() {
                Ok("aarch64-unknown-linux-musl")
            } else {
                Ok("aarch64-unknown-linux-gnu")
            }
        }
        ("linux", "arm") => Ok("armv7-unknown-linux-gnueabihf"),
        ("linux", "x86") => Ok("i686-unknown-linux-gnu"),
        ("macos", "x86_64") => Ok("x86_64-apple-darwin"),
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        ("windows", "x86_64") => Ok("x86_64-pc-windows-msvc"),
        _ => Err(format!("Unsupported platform: {}-{}", OS, ARCH)),
    }
}

/// Detect if running on musl libc.
fn is_musl() -> bool {
    // Check /etc/alpine-release for Alpine
    if std::path::Path::new("/etc/alpine-release").exists() {
        return true;
    }
    // Check ldd output
    if let Ok(output) = std::process::Command::new("ldd").arg("--version").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stdout.contains("musl") || stderr.contains("musl") {
            return true;
        }
    }
    false
}

/// Parse version string, removing 'v' prefix.
fn parse_version(v: &str) -> &str {
    v.strip_prefix('v').unwrap_or(v)
}

/// Compare two version strings.
/// Returns: -1 if a < b, 0 if a == b, 1 if a > b.
fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let a = parse_version(a);
    let b = parse_version(b);

    let a_parts: Vec<u32> = a.split('.').filter_map(|s| s.parse().ok()).collect();
    let b_parts: Vec<u32> = b.split('.').filter_map(|s| s.parse().ok()).collect();

    for (a, b) in a_parts.iter().zip(b_parts.iter()) {
        match a.cmp(b) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    a_parts.len().cmp(&b_parts.len())
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub async fn run(args: UpgradeArgs) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let current_version = env!("CARGO_PKG_VERSION");
    let binary_name = args.binary.as_deref().unwrap_or("trojan");

    println!("Current version: v{}", current_version);

    let client = Client::builder().user_agent(USER_AGENT).build()?;

    // Get release info
    let (latest_version, assets) = if let Some(ref ver) = args.target {
        let version = if ver.starts_with('v') {
            ver.clone()
        } else {
            format!("v{}", ver)
        };
        println!("Fetching release {}...", version);
        let url = format!(
            "https://api.github.com/repos/trojan-rust/trojan-rust/releases/tags/{}",
            version
        );
        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            return Err(format!(
                "Failed to fetch release {}: {} {}",
                version,
                response.status(),
                response.text().await.unwrap_or_default()
            )
            .into());
        }
        let release: Release = response.json().await?;
        (release.tag_name, release.assets)
    } else {
        println!("Checking for updates...");
        let response = client.get(GITHUB_API).send().await?;
        if !response.status().is_success() {
            return Err(format!(
                "Failed to fetch latest release: {} {}",
                response.status(),
                response.text().await.unwrap_or_default()
            )
            .into());
        }
        let release: Release = response.json().await?;
        (release.tag_name, release.assets)
    };

    println!("Latest version: {}", latest_version);

    // Compare versions
    let cmp = compare_versions(current_version, &latest_version);
    match cmp {
        std::cmp::Ordering::Equal => {
            println!("Already running the latest version.");
            if !args.force {
                return Ok(());
            }
            println!("Force reinstalling...");
        }
        std::cmp::Ordering::Greater => {
            println!("Current version is newer than the latest release.");
            if !args.force {
                return Ok(());
            }
            println!("Force downgrading...");
        }
        std::cmp::Ordering::Less => {
            println!(
                "New version available: {} -> {}",
                current_version, latest_version
            );
        }
    }

    if args.check {
        return Ok(());
    }

    // Determine target and find asset
    let target = get_target_triple()?;
    println!("Target: {}", target);

    let archive_name = if OS == "windows" {
        format!("{}-{}.zip", binary_name, target)
    } else {
        format!("{}-{}.tar.gz", binary_name, target)
    };

    let asset = assets
        .iter()
        .find(|a| a.name == archive_name)
        .ok_or_else(|| format!("No release found for {}", archive_name))?;

    println!("Downloading {}...", asset.name);

    // Download to temp file
    let temp_dir = tempfile::tempdir()?;
    let archive_path = temp_dir.path().join(&asset.name);

    let response = client.get(&asset.browser_download_url).send().await?;
    let total_size = response.content_length().unwrap_or(0);

    let mut file = tokio::fs::File::create(&archive_path).await?;
    let mut downloaded: u64 = 0;
    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        file.write_all(&chunk).await?;
        downloaded += chunk.len() as u64;

        if total_size > 0 {
            let pct = (downloaded as f64 / total_size as f64 * 100.0) as u32;
            print!("\rDownloading: {}% ({}/{})", pct, downloaded, total_size);
            io::stdout().flush()?;
        }
    }
    println!();

    // Verify checksum if available
    if !args.no_verify {
        let checksum_name = "SHA256SUMS";
        if let Some(checksum_asset) = assets.iter().find(|a| a.name == checksum_name) {
            println!("Verifying checksum...");
            let checksums = client
                .get(&checksum_asset.browser_download_url)
                .send()
                .await?
                .text()
                .await?;

            let expected = checksums
                .lines()
                .find(|line| line.contains(&asset.name))
                .and_then(|line| line.split_whitespace().next())
                .ok_or("Checksum not found for asset")?;

            let file_data = tokio::fs::read(&archive_path).await?;
            let mut hasher = Sha256::new();
            hasher.update(&file_data);
            let actual = hex::encode(hasher.finalize());

            if actual != expected {
                return Err(format!(
                    "Checksum mismatch!\n  Expected: {}\n  Actual: {}",
                    expected, actual
                )
                .into());
            }
            println!("Checksum verified.");
        } else {
            println!("Warning: No checksum file found, skipping verification.");
        }
    }

    // Extract binary
    println!("Extracting...");
    let binary_path = if OS == "windows" {
        extract_zip(&archive_path, temp_dir.path(), binary_name)?
    } else {
        extract_tar_gz(&archive_path, temp_dir.path(), binary_name)?
    };

    // Replace current binary
    println!("Installing...");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&binary_path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&binary_path, perms)?;
    }

    // Use self_replace for safe binary replacement
    self_replace::self_replace(&binary_path)?;

    println!(
        "Upgrade complete: v{} -> {}",
        current_version, latest_version
    );
    println!("Please restart the service to use the new version.");

    Ok(())
}

fn extract_tar_gz(
    archive_path: &std::path::Path,
    dest_dir: &std::path::Path,
    binary_name: &str,
) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let file = std::fs::File::open(archive_path)?;
    let decoder = GzDecoder::new(file);
    let mut archive = Archive::new(decoder);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;

        // Look for the binary (might be at root or in a subdirectory)
        if let Some(name) = path.file_name()
            && name == binary_name
        {
            let dest_path = dest_dir.join(binary_name);
            entry.unpack(&dest_path)?;
            return Ok(dest_path);
        }
    }

    Err(format!("Binary '{}' not found in archive", binary_name).into())
}

#[cfg(windows)]
fn extract_zip(
    archive_path: &std::path::Path,
    dest_dir: &std::path::Path,
    binary_name: &str,
) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let file = std::fs::File::open(archive_path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    let exe_name = format!("{}.exe", binary_name);

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let path = file.name();

        if path.ends_with(&exe_name) {
            let dest_path = dest_dir.join(&exe_name);
            let mut outfile = std::fs::File::create(&dest_path)?;
            std::io::copy(&mut file, &mut outfile)?;
            return Ok(dest_path);
        }
    }

    Err(format!("Binary '{}' not found in archive", exe_name).into())
}

#[cfg(not(windows))]
fn extract_zip(
    _archive_path: &std::path::Path,
    _dest_dir: &std::path::Path,
    _binary_name: &str,
) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    Err("ZIP extraction not supported on this platform".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_versions() {
        use std::cmp::Ordering;

        assert_eq!(compare_versions("0.1.0", "0.1.0"), Ordering::Equal);
        assert_eq!(compare_versions("v0.1.0", "0.1.0"), Ordering::Equal);
        assert_eq!(compare_versions("0.1.0", "v0.1.0"), Ordering::Equal);
        assert_eq!(compare_versions("0.1.0", "0.1.1"), Ordering::Less);
        assert_eq!(compare_versions("0.1.1", "0.1.0"), Ordering::Greater);
        assert_eq!(compare_versions("0.2.0", "0.1.9"), Ordering::Greater);
        assert_eq!(compare_versions("1.0.0", "0.9.9"), Ordering::Greater);
    }

    #[test]
    fn test_parse_version() {
        assert_eq!(parse_version("v0.1.0"), "0.1.0");
        assert_eq!(parse_version("0.1.0"), "0.1.0");
    }
}
