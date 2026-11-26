//! Automatic certificates via ACME HTTP-01 (Let's Encrypt and compatible CAs).
//!
//! [`AcmeManager`] keeps an account key and certificate on disk, publishes
//! HTTP-01 responses through the shared [`ChallengeStore`] (which the proxy's
//! plain-HTTP listener serves), installs issued certificates into the
//! [`SniResolver`] without a restart, and renews before expiry.

use crate::challenge::ChallengeStore;
use crate::tls::{load_certified_key, SniResolver, TlsError};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use velox_core::config::AcmeConfig;

/// Assumed certificate lifetime for renewal scheduling (Let's Encrypt: 90 days).
const ASSUMED_LIFETIME: Duration = Duration::from_secs(90 * 24 * 3600);
/// Upper bound for one issuance attempt.
const ISSUE_TIMEOUT: Duration = Duration::from_secs(300);

/// ACME failures.
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    /// Protocol or transport error from the ACME client.
    #[error("ACME protocol error: {0}")]
    Protocol(#[from] instant_acme::Error),
    /// Cache directory I/O failed.
    #[error("ACME cache I/O error at {path}: {source}")]
    Io {
        /// Path involved.
        path: String,
        /// Underlying error.
        source: std::io::Error,
    },
    /// Stored credentials could not be (de)serialised.
    #[error("ACME credential serialisation error: {0}")]
    Credentials(#[from] serde_json::Error),
    /// The CA did not offer an HTTP-01 challenge.
    #[error("CA offered no http-01 challenge for {0}")]
    NoHttp01(String),
    /// An authorization or order ended in a failure state.
    #[error("ACME order failed: {0}")]
    Order(String),
    /// Issuance exceeded its time budget.
    #[error("ACME issuance timed out")]
    Timeout,
    /// The issued material could not be loaded.
    #[error(transparent)]
    Tls(#[from] TlsError),
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> AcmeError + '_ {
    move |source| AcmeError::Io { path: path.display().to_string(), source }
}

/// Obtains and renews certificates for the configured domains.
#[derive(Debug)]
pub struct AcmeManager {
    cfg: AcmeConfig,
    challenges: Arc<ChallengeStore>,
    resolver: Arc<SniResolver>,
}

impl AcmeManager {
    /// Create a manager bound to the given challenge store and resolver.
    pub fn new(cfg: AcmeConfig, challenges: Arc<ChallengeStore>, resolver: Arc<SniResolver>) -> Self {
        Self { cfg, challenges, resolver }
    }

    fn dir(&self) -> PathBuf {
        let name = self.cfg.domains.first().map_or("default", String::as_str);
        self.cfg.cache_dir.join(name.replace(['/', '\\', '*'], "_"))
    }

    fn cert_path(&self) -> PathBuf {
        self.dir().join("fullchain.pem")
    }

    fn key_path(&self) -> PathBuf {
        self.dir().join("privkey.pem")
    }

    /// Time until the cached certificate should be renewed (zero if due or absent).
    fn renew_in(&self) -> Option<Duration> {
        let issued = std::fs::metadata(self.cert_path()).ok()?.modified().ok()?;
        let age = SystemTime::now().duration_since(issued).unwrap_or_default();
        let renew_after =
            ASSUMED_LIFETIME.saturating_sub(Duration::from_secs(u64::from(self.cfg.renew_before_days) * 24 * 3600));
        Some(renew_after.saturating_sub(age))
    }

    fn install(&self) -> Result<(), AcmeError> {
        let ck = load_certified_key(&self.cert_path(), &self.key_path())?;
        for d in &self.cfg.domains {
            self.resolver.set_dynamic(d, Arc::clone(&ck));
        }
        Ok(())
    }

    /// Ensure a valid certificate is installed; returns when to check again.
    pub async fn ensure(&self) -> Result<Duration, AcmeError> {
        if let Some(wait) = self.renew_in() {
            if !wait.is_zero() && self.install().is_ok() {
                return Ok(wait);
            }
        }
        tokio::time::timeout(ISSUE_TIMEOUT, self.obtain()).await.map_err(|_| AcmeError::Timeout)??;
        self.install()?;
        Ok(self.renew_in().unwrap_or(Duration::from_secs(24 * 3600)))
    }

    async fn account(&self) -> Result<Account, AcmeError> {
        let path = self.cfg.cache_dir.join("account.json");
        if let Ok(text) = tokio::fs::read(&path).await {
            let creds: AccountCredentials = serde_json::from_slice(&text)?;
            return Ok(Account::builder()?.from_credentials(creds).await?);
        }
        let contact = format!("mailto:{}", self.cfg.contact_email);
        let contacts = [contact.as_str()];
        let (account, creds) = Account::builder()?
            .create(
                &NewAccount { contact: &contacts, terms_of_service_agreed: true, only_return_existing: false },
                self.cfg.directory_url.clone(),
                None,
            )
            .await?;
        tokio::fs::create_dir_all(&self.cfg.cache_dir).await.map_err(io_err(&self.cfg.cache_dir))?;
        write_private(&path, serde_json::to_string_pretty(&creds)?.as_bytes()).await?;
        Ok(account)
    }

    /// Run a full HTTP-01 order and write the result to the cache directory.
    pub async fn obtain(&self) -> Result<(), AcmeError> {
        let account = self.account().await?;
        let identifiers: Vec<Identifier> = self.cfg.domains.iter().cloned().map(Identifier::Dns).collect();
        let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;
        let mut tokens: Vec<String> = Vec::new();
        {
            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                let mut authz = result?;
                match authz.status {
                    AuthorizationStatus::Pending => {}
                    AuthorizationStatus::Valid => continue,
                    other => return Err(AcmeError::Order(format!("authorization is {other:?}"))),
                }
                let mut challenge = authz
                    .challenge(ChallengeType::Http01)
                    .ok_or_else(|| AcmeError::NoHttp01(self.cfg.domains.join(",")))?;
                let token = challenge.token.clone();
                self.challenges.insert(token.clone(), challenge.key_authorization().as_str().to_owned());
                tokens.push(token);
                challenge.set_ready().await?;
            }
        }
        let result = async {
            let status = order.poll_ready(&RetryPolicy::default()).await?;
            if status != OrderStatus::Ready {
                return Err(AcmeError::Order(format!("order status {status:?}")));
            }
            let key_pem = order.finalize().await?;
            let chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;
            Ok::<_, AcmeError>((key_pem, chain_pem))
        }
        .await;
        for t in &tokens {
            self.challenges.remove(t);
        }
        let (key_pem, chain_pem) = result?;
        let dir = self.dir();
        tokio::fs::create_dir_all(&dir).await.map_err(io_err(&dir))?;
        write_private(&self.key_path(), key_pem.as_bytes()).await?;
        tokio::fs::write(self.cert_path(), chain_pem).await.map_err(io_err(&self.cert_path()))?;
        Ok(())
    }

    /// Issue/renew forever (until `cancel` fires), logging failures.
    pub async fn run(self: Arc<Self>, cancel: tokio_util::sync::CancellationToken) {
        loop {
            let wait = match self.ensure().await {
                Ok(w) => w,
                Err(e) => {
                    tracing::warn!(error = %e, "ACME certificate management failed; retrying in 1h");
                    Duration::from_secs(3600)
                }
            };
            tokio::select! {
                () = cancel.cancelled() => return,
                () = tokio::time::sleep(wait.max(Duration::from_secs(60))) => {}
            }
        }
    }
}

async fn write_private(path: &Path, data: &[u8]) -> Result<(), AcmeError> {
    tokio::fs::write(path, data).await.map_err(io_err(path))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await.map_err(io_err(path))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use velox_core::config::TlsConfig;

    fn manager(dir: &Path) -> AcmeManager {
        AcmeManager::new(
            AcmeConfig {
                domains: vec!["example.test".into()],
                contact_email: "ops@example.test".into(),
                directory_url: "https://127.0.0.1:1/dir".into(),
                cache_dir: dir.to_owned(),
                renew_before_days: 30,
            },
            Arc::new(ChallengeStore::default()),
            SniResolver::from_config(&TlsConfig::default()).unwrap(),
        )
    }

    #[tokio::test]
    async fn cached_fresh_certificate_is_installed_without_contacting_the_ca() {
        let dir = tempfile::tempdir().unwrap();
        let m = manager(dir.path());
        let g = rcgen::generate_simple_self_signed(vec!["example.test".to_owned()]).unwrap();
        std::fs::create_dir_all(m.dir()).unwrap();
        std::fs::write(m.cert_path(), g.cert.pem()).unwrap();
        std::fs::write(m.key_path(), g.key_pair.serialize_pem()).unwrap();
        let wait = m.ensure().await.unwrap();
        assert!(wait > Duration::from_secs(50 * 24 * 3600), "renewal scheduled far ahead: {wait:?}");
        assert!(m.resolver.resolve_name(Some("example.test")).is_some());
    }

    #[tokio::test]
    async fn unreachable_ca_surfaces_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let m = manager(dir.path());
        assert!(m.ensure().await.is_err());
        assert!(m.challenges.is_empty());
    }
}
