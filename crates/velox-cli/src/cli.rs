//! The `velox` command line.

use crate::app::App;
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use velox_core::Config;

/// Velox: a fast, memory-safe reverse proxy and load balancer.
#[derive(Debug, Parser)]
#[command(name = "velox", version, about, long_about = None)]
pub struct Cli {
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the proxy.
    Start {
        /// Path to `velox.toml`.
        #[arg(short, long, default_value = "velox.toml")]
        config: PathBuf,
    },
    /// Validate a configuration file and exit (non-zero on any problem).
    Validate {
        /// Path to `velox.toml`.
        #[arg(short, long, default_value = "velox.toml")]
        config: PathBuf,
    },
    /// Ask a running instance to re-read its configuration file.
    Reload {
        /// Config file used to discover the admin address.
        #[arg(short, long, default_value = "velox.toml")]
        config: PathBuf,
        /// Admin API address (overrides the config file).
        #[arg(long)]
        admin: Option<SocketAddr>,
    },
    /// Print version information.
    Version,
}

/// Execute a parsed command line.
pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Version => {
            println!("velox {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Validate { config } => {
            let summary = validate(&config)?;
            println!("{summary}");
            Ok(())
        }
        Command::Reload { config, admin } => {
            let addr = match admin {
                Some(a) => a,
                None => {
                    Config::load(&config)?.admin.addr.context("the configuration has no [admin] addr; pass --admin")?
                }
            };
            let token = std::env::var("VELOX_ADMIN_TOKEN").ok().filter(|t| !t.is_empty());
            let (status, body) = admin_post(addr, "/admin/v1/reload", token.as_deref()).await?;
            if status == 200 {
                println!("reloaded: {}", body.trim());
                Ok(())
            } else {
                bail!("reload failed (HTTP {status}): {}", body.trim())
            }
        }
        Command::Start { config } => start(&config).await,
    }
}

/// Validate `path` and return a human-readable summary.
pub fn validate(path: &Path) -> Result<String> {
    let cfg = Config::load(path)?;
    cfg.validate_files()?;
    let backends: usize = cfg.upstreams.iter().map(|u| u.backends.len()).sum();
    Ok(format!(
        "{}: OK ({} route(s), {} upstream(s), {} backend(s), {} tcp proxy(ies))",
        path.display(),
        cfg.routes.len(),
        cfg.upstreams.len(),
        backends,
        cfg.tcp_proxies.len()
    ))
}

/// POST to the admin API with a tiny dependency-free HTTP/1.1 client.
pub async fn admin_post(addr: SocketAddr, path: &str, token: Option<&str>) -> Result<(u16, String)> {
    let work = async {
        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .with_context(|| format!("cannot connect to the admin API at {addr} (is velox running?)"))?;
        let auth = token.map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
        let req =
            format!("POST {path} HTTP/1.1\r\nHost: {addr}\r\n{auth}Content-Length: 0\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await?;
        let text = String::from_utf8_lossy(&raw).into_owned();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .context("malformed response from the admin API")?;
        let body = text.split_once("\r\n\r\n").map_or(String::new(), |(_, b)| b.to_owned());
        Ok::<_, anyhow::Error>((status, body))
    };
    tokio::time::timeout(Duration::from_secs(10), work).await.context("timed out talking to the admin API")?
}

async fn start(path: &Path) -> Result<()> {
    let cfg = Config::load(path)?;
    cfg.validate_files()?;
    velox_telemetry::init_logging(&cfg.telemetry)?;
    let app = App::start(cfg, Some(path.to_owned())).await?;
    wait_for_signals(&app).await?;
    tracing::info!("shutdown signal received; draining connections");
    let clean = app.shutdown().await;
    if clean {
        tracing::info!("shutdown complete");
    } else {
        tracing::warn!("drain timeout reached; remaining connections were closed");
    }
    Ok(())
}

/// Block until SIGINT/SIGTERM; SIGHUP triggers a reload.
async fn wait_for_signals(app: &App) -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    let mut hup = signal(SignalKind::hangup())?;
    loop {
        tokio::select! {
            _ = term.recv() => return Ok(()),
            _ = int.recv() => return Ok(()),
            _ = hup.recv() => {
                let reloader = std::sync::Arc::clone(&app.reloader);
                let metrics = std::sync::Arc::clone(&app.metrics);
                // File I/O + cert parsing: keep it off the reactor.
                let ok = tokio::task::spawn_blocking(move || reloader.reload().is_ok()).await.unwrap_or(false);
                metrics.config_reload(ok);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_subcommands() {
        let c = Cli::try_parse_from(["velox", "start", "-c", "x.toml"]).unwrap();
        assert!(matches!(c.command, Command::Start { config } if config.as_path() == Path::new("x.toml")));
        let c = Cli::try_parse_from(["velox", "reload", "--admin", "127.0.0.1:9901"]).unwrap();
        assert!(matches!(c.command, Command::Reload { admin: Some(_), .. }));
        assert!(Cli::try_parse_from(["velox", "bogus"]).is_err());
    }

    #[test]
    fn validate_reports_ok_and_errors() {
        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("good.toml");
        std::fs::write(
            &good,
            "[server]\nhttp_addr=\"127.0.0.1:1\"\n[[upstream]]\nname=\"a\"\nbackends=[{addr=\"127.0.0.1:2\"}]\n[[route]]\nupstream=\"a\"\n",
        )
        .unwrap();
        assert!(validate(&good).unwrap().contains("1 route(s), 1 upstream(s), 1 backend(s)"));
        let bad = dir.path().join("bad.toml");
        std::fs::write(&bad, "[server]\nhttp_addr=\"127.0.0.1:1\"\n[[route]]\nupstream=\"missing\"\n").unwrap();
        let err = format!("{:#}", validate(&bad).unwrap_err());
        assert!(err.contains("unknown upstream"), "{err}");
        assert!(validate(&dir.path().join("nope.toml")).is_err());
    }
}

#[cfg(test)]
mod sample_config {
    use super::*;

    /// The shipped `velox.toml` must always parse, validate and boot.
    #[test]
    fn repository_sample_config_is_valid() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../velox.toml");
        let summary = validate(&path).expect("sample config must validate");
        assert!(summary.contains("1 route(s)"), "{summary}");
        let cfg = Config::load(&path).unwrap();
        assert!(cfg.server.h3 && cfg.server.https_addr.is_some());
        assert!(cfg.tls.self_signed_fallback);
    }
}
