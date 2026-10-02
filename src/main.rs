mod auth;
mod config;
mod electrum;
mod header;
mod store;
mod sync;
mod wallet;
mod web;

use std::io::BufRead;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, bail};
use clap::Parser;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::config::{Cli, Command, Config};

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_env("HONEYBEE_LOG").unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
    let cli = Cli::parse();
    let result = match cli.command {
        Some(Command::HashPassword) => hash_password_cmd(),
        Some(Command::Serve) | None => serve(cli.config).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

fn hash_password_cmd() -> anyhow::Result<()> {
    eprintln!("Enter the password, then press Enter (tip: `read -rs PW; echo \"$PW\" | honeybee hash-password`):");
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    let password = line.trim_end_matches(['\r', '\n']);
    if password.chars().count() < 8 {
        bail!("use at least 8 characters");
    }
    println!("{}", auth::hash_password(password)?);
    Ok(())
}

async fn serve(cfg: Config) -> anyhow::Result<()> {
    let password_hash = match (&cfg.password_hash, &cfg.password) {
        (Some(hash), _) => {
            auth::validate_hash(hash).context("HONEYBEE_PASSWORD_HASH is not a valid hash")?;
            Some(hash.trim().to_string())
        }
        (None, Some(pw)) if !pw.is_empty() => Some(auth::hash_password(pw)?),
        _ => None,
    };
    if password_hash.is_none() {
        if !cfg.listen.ip().is_loopback() && !cfg.no_auth {
            bail!(
                "refusing to listen on {} without a password. Set HONEYBEE_PASSWORD_HASH (see `honeybee hash-password`), \
                 or HONEYBEE_NO_AUTH=true if an authenticating reverse proxy sits in front.",
                cfg.listen
            );
        }
        warn!("authentication is disabled");
    }

    std::fs::create_dir_all(&cfg.data_dir).with_context(|| format!("creating {}", cfg.data_dir.display()))?;
    restrict_permissions(&cfg.data_dir, 0o700);
    let db_path = cfg.data_dir.join("honeybee.db");
    let store = Arc::new(store::Store::open(&db_path)?);
    restrict_permissions(&db_path, 0o600);

    let secret: [u8; 32] = match store.meta("session_secret")? {
        Some(s) if s.len() == 32 => s.try_into().expect("32 bytes"),
        _ => {
            let s: [u8; 32] = rand::random();
            store.set_meta("session_secret", &s)?;
            s
        }
    };

    let client = electrum::ElectrumClient::new(&cfg.electrum, cfg.electrum_ca_file.as_deref(), cfg.electrum_insecure)?;
    info!("electrum server: {}, network: {}", client.endpoint(), cfg.network);
    client.spawn();
    let mgr = sync::Manager::new(client, store.clone(), cfg.network)?;
    mgr.start();

    let state = web::AppState {
        mgr,
        store,
        auth: Arc::new(auth::Auth::new(password_hash, secret)),
        cfg: Arc::new(cfg.clone()),
    };
    let app = web::router(state);
    let listener =
        tokio::net::TcpListener::bind(cfg.listen).await.with_context(|| format!("binding {}", cfg.listen))?;
    info!("Honeybee {} listening on http://{}", env!("CARGO_PKG_VERSION"), cfg.listen);
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// The database holds xpubs, so keep it (and SQLite's -wal/-shm files) private.
fn restrict_permissions(path: &std::path::Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
            warn!("could not restrict permissions on {}: {e}", path.display());
        }
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("shutting down");
}
