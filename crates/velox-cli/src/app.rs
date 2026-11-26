//! Wires every component into a running Velox instance.

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use velox_admin::{AdminApi, Reloader};
use velox_core::{Config, SharedState};
use velox_health::{DnsRefresher, HealthChecker, Resolver, SystemResolver};
use velox_proxy::{Proxy, Running, Shutdown};
use velox_security::{ChallengeStore, SniResolver};
use velox_telemetry::Metrics;

/// Reloads configuration from a file and re-reads TLS material.
#[derive(Debug)]
pub struct FileReloader {
    path: PathBuf,
    state: Arc<SharedState>,
    tls: Option<Arc<SniResolver>>,
}

impl FileReloader {
    /// Create a reloader for `path`.
    pub fn new(path: PathBuf, state: Arc<SharedState>, tls: Option<Arc<SniResolver>>) -> Self {
        Self { path, state, tls }
    }

    fn reload_inner(&self) -> Result<u64> {
        let cfg = Config::load(&self.path)?;
        cfg.validate_files()?;
        let live = self.state.load();
        let (old, new) = (&live.config.server, &cfg.server);
        if old.http_addr != new.http_addr
            || old.https_addr != new.https_addr
            || old.h3_addr != new.h3_addr
            || old.h3 != new.h3
            || old.proxy_protocol != new.proxy_protocol
            || live
                .config
                .tcp_proxies
                .iter()
                .map(|t| t.proxy_protocol)
                .ne(cfg.tcp_proxies.iter().map(|t| t.proxy_protocol))
            || live.config.tcp_proxies.iter().map(|t| t.listen).ne(cfg.tcp_proxies.iter().map(|t| t.listen))
        {
            tracing::warn!(
                "listener addresses changed in the config file; this requires a restart and was NOT applied"
            );
        }
        // Certificates first: if they cannot be loaded nothing is swapped.
        if let Some(tls) = &self.tls {
            tls.reload(&cfg.tls).context("reloading TLS certificates")?;
        }
        let snap = self.state.apply(cfg)?;
        Ok(snap.generation)
    }
}

impl Reloader for FileReloader {
    fn reload(&self) -> Result<u64, String> {
        match self.reload_inner() {
            Ok(g) => {
                tracing::info!(generation = g, path = %self.path.display(), "configuration reloaded");
                Ok(g)
            }
            Err(e) => {
                tracing::error!(error = %e, "configuration reload failed; keeping previous configuration");
                Err(format!("{e:#}"))
            }
        }
    }
}

/// A running Velox instance.
pub struct App {
    /// Live configuration state.
    pub state: Arc<SharedState>,
    /// Metrics registry.
    pub metrics: Arc<Metrics>,
    /// The data-plane engine.
    pub proxy: Arc<Proxy>,
    /// Bound data-plane addresses.
    pub running: Running,
    /// Bound admin API address.
    pub admin_addr: Option<SocketAddr>,
    /// Bound dedicated metrics address.
    pub metrics_addr: Option<SocketAddr>,
    /// The reloader (also used by SIGHUP).
    pub reloader: Arc<dyn Reloader>,
    aux_cancel: CancellationToken,
    aux: Vec<JoinHandle<()>>,
}

impl App {
    /// Start everything described by `config`.
    ///
    /// `config_path` enables file-based reloads; without it `reload` fails
    /// with a clear message (API/state edits still work).
    pub async fn start(config: Config, config_path: Option<PathBuf>) -> Result<Self> {
        Self::start_with_resolver(config, config_path, Arc::new(SystemResolver)).await
    }

    /// [`App::start`] with a custom resolver for periodic backend DNS refresh
    /// (service discovery, or a scripted resolver in tests).
    pub async fn start_with_resolver(
        config: Config,
        config_path: Option<PathBuf>,
        resolver: Arc<dyn Resolver>,
    ) -> Result<Self> {
        let state = SharedState::new(config.clone())?;
        let metrics = Arc::new(Metrics::new()?);
        let challenges = Arc::new(ChallengeStore::default());
        let shutdown = Shutdown::new();
        let aux_cancel = CancellationToken::new();
        let mut aux = Vec::new();

        let needs_tls = config.server.https_addr.is_some() || config.tls.acme.is_some();
        let tls = if needs_tls {
            Some(SniResolver::from_config(&config.tls).context("loading TLS certificates")?)
        } else {
            None
        };

        if let Some(acme) = &config.tls.acme {
            #[cfg(feature = "acme")]
            {
                let resolver = tls.clone().context("ACME requires a TLS resolver")?;
                let mgr =
                    Arc::new(velox_security::acme::AcmeManager::new(acme.clone(), Arc::clone(&challenges), resolver));
                aux.push(tokio::spawn(mgr.run(aux_cancel.clone())));
            }
            #[cfg(not(feature = "acme"))]
            {
                let _ = acme;
                anyhow::bail!("`[tls.acme]` is configured but this binary was built without the `acme` feature (rebuild with `--features acme`)");
            }
        }

        let proxy = Proxy::new(Arc::clone(&state), Arc::clone(&metrics), challenges, shutdown);
        let running = velox_proxy::start(Arc::clone(&proxy), tls.clone()).await.context("starting listeners")?;

        // Background health checking follows the proxy's drain signal.
        aux.push(HealthChecker::new(Arc::clone(&state), aux_cancel.clone()).spawn());
        aux.push(
            DnsRefresher::new(Arc::clone(&state), aux_cancel.clone())
                .with_resolver(resolver)
                .with_metrics(Arc::clone(&metrics))
                .spawn(),
        );

        let reloader: Arc<dyn Reloader> = match config_path {
            Some(path) => Arc::new(FileReloader::new(path, Arc::clone(&state), tls)),
            None => Arc::new(NoFile),
        };
        let token = config.admin.token_env.as_deref().and_then(|var| std::env::var(var).ok()).filter(|t| !t.is_empty());
        let cache: Arc<dyn velox_core::cache_admin::CacheAdmin> = Arc::clone(&proxy) as _;
        let api =
            AdminApi::with_cache(Arc::clone(&state), Arc::clone(&metrics), Arc::clone(&reloader), token, Some(cache));

        let mut admin_addr = None;
        if let Some(addr) = config.admin.addr {
            let (bound, handle) = velox_admin::serve(addr, Arc::clone(&api), aux_cancel.clone()).await?;
            admin_addr = Some(bound);
            aux.push(handle);
        }
        let mut metrics_addr = None;
        if let Some(addr) = config.telemetry.metrics_addr {
            let (bound, handle) = velox_admin::serve_metrics(addr, api, aux_cancel.clone()).await?;
            metrics_addr = Some(bound);
            aux.push(handle);
        }

        tracing::info!(
            http = ?running.http_addr,
            https = ?running.https_addr,
            h3 = ?running.h3_addr,
            admin = ?admin_addr,
            metrics = ?metrics_addr,
            "velox started"
        );
        Ok(Self { state, metrics, proxy, running, admin_addr, metrics_addr, reloader, aux_cancel, aux })
    }

    /// Gracefully stop: drain the data plane, then stop auxiliary services.
    /// Returns `true` if all in-flight work finished within the drain timeout.
    pub async fn shutdown(self) -> bool {
        let clean = self.running.shutdown().await;
        self.aux_cancel.cancel();
        for h in self.aux {
            let _ = h.await;
        }
        clean
    }
}

impl std::fmt::Debug for App {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("App")
            .field("running", &self.running)
            .field("admin_addr", &self.admin_addr)
            .finish_non_exhaustive()
    }
}

struct NoFile;

impl Reloader for NoFile {
    fn reload(&self) -> Result<u64, String> {
        Err("this instance was started without a configuration file".to_owned())
    }
}
