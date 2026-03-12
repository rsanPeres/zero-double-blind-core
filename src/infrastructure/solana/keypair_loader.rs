//! Keypair discovery for the Solana off-chain client.
//!
//! Resolution order:
//! 1. `SOLANA_KEYPAIR` env-var — inline JSON `[..64..]` **or** a file path.
//! 2. `util/id.json`  (relative to the working directory).
//! 3. `util/config.yml` with a `keypair_path` field.
//! 4. Windows only: scan WSL distro home directories for `id.json`.
//!
//! No network I/O is performed here.

use anyhow::{bail, Context, Result};
use shellexpand::tilde;
use solana_sdk::signature::{read_keypair_file, Keypair};
use std::{fs, path::Path};

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Loads the default keypair, **panicking** on failure.
///
/// Intended for CLI / binary entry-points where a missing keypair is a fatal
/// misconfiguration.  Library callers should prefer [`load_keypair`].
pub fn payer() -> Keypair {
    load_keypair().expect(
        "could not load keypair — set SOLANA_KEYPAIR (file path or JSON [..64..]), \
         create util/id.json, or configure util/config.yml",
    )
}

/// Loads the default keypair, returning a descriptive error on failure.
pub fn load_keypair() -> Result<Keypair> {
    // 1) SOLANA_KEYPAIR env-var
    if let Ok(v) = std::env::var("SOLANA_KEYPAIR") {
        if let Some(kp) = parse_inline_or_path(&v)
            .context("SOLANA_KEYPAIR: failed to parse value")?
        {
            return Ok(kp);
        }
    }

    // 2) util/id.json
    let id_path = Path::new("util").join("id.json");
    if id_path.exists() {
        return read_keypair_file(&id_path)
            .map_err(|e| anyhow::anyhow!("failed to read keypair from {}: {}", id_path.display(), e));
    }

    // 3) util/config.yml  (keypair_path field)
    let cfg_path = Path::new("util").join("config.yml");
    if cfg_path.exists() {
        #[derive(serde::Deserialize)]
        struct Cfg {
            keypair_path: Option<String>,
        }
        let f = fs::File::open(&cfg_path)
            .with_context(|| format!("failed to open {}", cfg_path.display()))?;
        if let Some(kp_path) = serde_yaml::from_reader::<_, Cfg>(f)
            .context("failed to parse util/config.yml")?
            .keypair_path
        {
            let expanded = tilde(&kp_path).into_owned();
            return read_keypair_file(&expanded)
                .map_err(|e| anyhow::anyhow!("failed to read keypair from {}: {}", expanded, e));
        }
    }

    // 4) Windows: scan WSL distros
    #[cfg(windows)]
    if let Some(kp) = try_wsl_keypair()? {
        return Ok(kp);
    }

    bail!(
        "keypair not found — set SOLANA_KEYPAIR (file path or JSON [..64..]), \
         create util/id.json, or populate util/config.yml with a keypair_path"
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Tries to parse `v` as either an inline JSON keypair (`[..64..]`) or a
/// file path.  Returns `Ok(None)` when neither form matches.
fn parse_inline_or_path(v: &str) -> Result<Option<Keypair>> {
    let s = v.trim();

    // Inline JSON array: [b0, b1, … b63]
    if s.starts_with('[') && s.ends_with(']') {
        let nums: Vec<u8> = serde_json::from_str(s)
            .context("SOLANA_KEYPAIR: failed to parse inline JSON keypair")?;
        if nums.len() != 64 {
            bail!(
                "SOLANA_KEYPAIR: inline JSON keypair must contain exactly 64 bytes, got {}",
                nums.len()
            );
        }
        return Ok(Some(
            Keypair::from_bytes(&nums).context("SOLANA_KEYPAIR: invalid keypair bytes")?,
        ));
    }

    // File path
    let p = tilde(s).into_owned();
    if Path::new(&p).exists() {
        return Ok(Some(
            read_keypair_file(&p)
                .map_err(|e| anyhow::anyhow!("Failed to read keypair from '{}': {}", p, e))?
        ));
    }

    Ok(None)
}

// ─────────────────────────────────────────────────────────────────────────────
// Windows / WSL helpers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(windows)]
fn try_wsl_keypair() -> Result<Option<Keypair>> {
    use std::path::PathBuf;

    // Explicit override via WSL_KEYPAIR
    if let Ok(linux_path) = std::env::var("WSL_KEYPAIR") {
        if let Some(p) = linux_path_to_unc(&linux_path)? {
            if p.exists() {
                return Ok(Some(
                    read_keypair_file(&p)
                        .with_context(|| format!("WSL_KEYPAIR: failed to read '{}'", p.display()))?,
                ));
            }
        }
    }

    // Auto-scan \\wsl$\<distro>\home\<user>\.config\solana\id.json
    let root = Path::new(r"\\wsl$");
    let entries = match fs::read_dir(root) {
        Ok(it) => it,
        Err(_) => return Ok(None), // WSL not available
    };

    // Username candidates: WSL_USERNAME > Windows USERNAME
    let user_guesses: Vec<String> = [
        std::env::var("WSL_USERNAME").ok(),
        std::env::var("USERNAME").ok(),
    ]
        .into_iter()
        .flatten()
        .collect();

    for de in entries.flatten() {
        let distro = de.file_name().to_string_lossy().to_string();
        let home = Path::new(r"\\wsl$").join(&distro).join("home");

        // Try known usernames first
        for u in &user_guesses {
            let p = home.join(u).join(".config").join("solana").join("id.json");
            if p.exists() {
                return Ok(Some(read_keypair_file(&p).with_context(|| {
                    format!("WSL: failed to read keypair at '{}'", p.display())
                })?));
            }
        }

        // Fall back to scanning up to 10 users in the distro's /home
        if let Ok(users) = fs::read_dir(&home) {
            for u in users.flatten().take(10) {
                let p = u.path().join(".config").join("solana").join("id.json");
                if p.exists() {
                    return Ok(Some(read_keypair_file(&p).with_context(|| {
                        format!("WSL: failed to read keypair at '{}'", p.display())
                    })?));
                }
            }
        }
    }

    Ok(None)
}

/// Converts a Linux path like `/home/user/...` to a WSL UNC path
/// `\\wsl$\<distro>\home\user\...`.  Returns `None` for non-`/home/` paths.
#[cfg(windows)]
fn linux_path_to_unc(linux: &str) -> Result<Option<std::path::PathBuf>> {
    if !linux.starts_with("/home/") {
        return Ok(None);
    }
    let sub = &linux[1..].replace('/', r"\"); // strip leading '/' then normalise

    // Prefer the explicit distro name from the environment
    if let Ok(distro) = std::env::var("WSL_DISTRO") {
        return Ok(Some(Path::new(r"\\wsl$").join(distro).join(sub)));
    }

    // Fall back to well-known distro names
    for distro in ["Ubuntu", "Ubuntu-22.04", "Ubuntu-20.04", "Debian"] {
        let p = Path::new(r"\\wsl$").join(distro).join(sub);
        if p.exists() {
            return Ok(Some(p));
        }
    }

    Ok(None)
}