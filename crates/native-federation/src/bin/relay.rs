//! Standalone Native federation relay for the experimental transport profile.
//!
//! This process owns one dedicated SQLite database and deliberately does not
//! mount into `serve`, `catalog.db`, or any ejectable user database.

use std::future::IntoFuture as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use native_federation::crypto::signing_key_from_base64url;
use native_federation::relay::Ed25519RelaySigner;
use native_federation::RelayClock;
use native_federation::{
    relay_router, PreverifiedSnapshotAuthority, Relay, RelayConfig, RelayLimits, SystemClock,
};

const ENV_DB: &str = "NATIVE_RELAY_DB";
const ENV_BIND: &str = "NATIVE_RELAY_BIND";
const ENV_ORIGIN: &str = "NATIVE_RELAY_PUBLIC_ORIGIN";
const ENV_AUTHORITY: &str = "NATIVE_RELAY_AUTHORITY_FILE";
const ENV_RELAY_ID: &str = "NATIVE_RELAY_ID";
const ENV_KEY_ID: &str = "NATIVE_RELAY_SIGNING_KID";
const ENV_KEY_SEED: &str = "NATIVE_RELAY_SIGNING_SEED";
const ENV_CLEANUP: &str = "NATIVE_RELAY_CLEANUP_SECS";
const ENV_SHUTDOWN: &str = "NATIVE_RELAY_SHUTDOWN_SECS";
const ENV_CONFORMANCE_CLOCK: &str = "NATIVE_RELAY_CONFORMANCE_CLOCK";
const ENV_DANGEROUS_PREVERIFIED: &str = "NATIVE_RELAY_DANGEROUS_ALLOW_PREVERIFIED_AUTHORITY";

#[derive(Debug)]
struct Config {
    db: PathBuf,
    bind: SocketAddr,
    public_origin: String,
    authority_file: PathBuf,
    relay_id: String,
    signing_kid: String,
    signing_seed: String,
    cleanup: Duration,
    shutdown: Duration,
    limits: RelayLimits,
    conformance_clock: Option<DateTime<Utc>>,
}

impl Config {
    fn from_env() -> Result<Self, String> {
        let db = PathBuf::from(optional(ENV_DB).unwrap_or_else(|| "./relay.db".into()));
        if db.file_name().and_then(|value| value.to_str()) == Some("catalog.db") {
            return Err("NATIVE_RELAY_DB must not point at catalog.db".into());
        }
        let bind: SocketAddr = optional(ENV_BIND)
            .unwrap_or_else(|| "0.0.0.0:8081".into())
            .parse()
            .map_err(|_| "NATIVE_RELAY_BIND is not a socket address".to_string())?;
        let public_origin = required(ENV_ORIGIN)?;
        let origin = url::Url::parse(&public_origin)
            .map_err(|_| "NATIVE_RELAY_PUBLIC_ORIGIN is invalid".to_string())?;
        let loopback_authority_adapter = bind.ip().is_loopback()
            && matches!(origin.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
        let dangerous_preverified = optional(ENV_DANGEROUS_PREVERIFIED).as_deref() == Some("1");
        if !loopback_authority_adapter && !dangerous_preverified {
            return Err(format!(
                "the preverified authority-file adapter is development-only; set {ENV_DANGEROUS_PREVERIFIED}=1 only when an authenticated upstream owns the file"
            ));
        }
        let mut limits = RelayLimits::default();
        limits.mailbox_bytes = integer("NATIVE_RELAY_MAILBOX_BYTES", limits.mailbox_bytes)?;
        limits.mailbox_deliveries =
            integer("NATIVE_RELAY_MAILBOX_DELIVERIES", limits.mailbox_deliveries)?;
        limits.sender_requests_per_minute = integer(
            "NATIVE_RELAY_SENDER_REQUESTS_PER_MINUTE",
            limits.sender_requests_per_minute,
        )?;
        limits.sender_deliveries_per_day = integer(
            "NATIVE_RELAY_SENDER_DELIVERIES_PER_DAY",
            limits.sender_deliveries_per_day,
        )?;
        limits.recipient_ingress_per_day = integer(
            "NATIVE_RELAY_RECIPIENT_INGRESS_PER_DAY",
            limits.recipient_ingress_per_day,
        )?;
        limits.source_requests_per_minute = integer(
            "NATIVE_RELAY_SOURCE_REQUESTS_PER_MINUTE",
            limits.source_requests_per_minute,
        )?;
        limits.lease_duration = Duration::from_secs(integer(
            "NATIVE_RELAY_LEASE_SECS",
            limits.lease_duration.as_secs() as i64,
        )? as u64);
        limits.default_expiry = Duration::from_secs(integer(
            "NATIVE_RELAY_DEFAULT_EXPIRY_SECS",
            limits.default_expiry.as_secs() as i64,
        )? as u64);
        limits.retention = Duration::from_secs(integer(
            "NATIVE_RELAY_RETENTION_SECS",
            limits.retention.as_secs() as i64,
        )? as u64);
        Ok(Self {
            db,
            bind,
            public_origin,
            authority_file: PathBuf::from(required(ENV_AUTHORITY)?),
            relay_id: required(ENV_RELAY_ID)?,
            signing_kid: required(ENV_KEY_ID)?,
            signing_seed: required(ENV_KEY_SEED)?,
            cleanup: Duration::from_secs(integer(ENV_CLEANUP, 300)? as u64),
            shutdown: Duration::from_secs(integer(ENV_SHUTDOWN, 8)? as u64),
            limits,
            conformance_clock: optional(ENV_CONFORMANCE_CLOCK)
                .map(|value| {
                    DateTime::parse_from_rfc3339(&value)
                        .map(|time| time.with_timezone(&Utc))
                        .map_err(|_| {
                            format!("{ENV_CONFORMANCE_CLOCK} must be an RFC 3339 timestamp")
                        })
                })
                .transpose()?,
        })
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("relay failed: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    let authority = Arc::new(PreverifiedSnapshotAuthority::from_path(
        &config.authority_file,
    )?);
    let signer = Arc::new(Ed25519RelaySigner::new(
        config.relay_id.clone(),
        config.signing_kid.clone(),
        signing_key_from_base64url(&config.signing_seed)?,
    )?);
    let clock: Arc<dyn RelayClock> = match config.conformance_clock {
        Some(now) => {
            eprintln!("relay is using the explicit conformance-only clock override");
            Arc::new(FixedClock(now))
        }
        None => Arc::new(SystemClock),
    };
    let relay = Relay::open(
        &config.db,
        RelayConfig {
            public_origin: config.public_origin.clone(),
            limits: config.limits.clone(),
        },
        authority,
        signer,
        clock,
    )
    .await?;
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    let cleanup = {
        let relay = relay.clone();
        let interval = config.cleanup;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                if let Err(error) = relay.cleanup().await {
                    // Identifiers and ciphertext never enter this operational log.
                    eprintln!("relay cleanup failed: {}", error.code);
                }
            }
        })
    };
    let (signal_seen, mut signal_noticed) = tokio::sync::oneshot::channel();
    let graceful = async move {
        shutdown_signal().await;
        let _ = signal_seen.send(());
    };
    let server = axum::serve(
        listener,
        relay_router(relay.clone()).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(graceful)
    .into_future();
    tokio::pin!(server);
    let result: Result<(), Box<dyn std::error::Error>> = tokio::select! {
        result = &mut server => result.map_err(|error| Box::new(error) as Box<dyn std::error::Error>),
        _ = &mut signal_noticed => {
            match tokio::time::timeout(config.shutdown, &mut server).await {
                Ok(result) => result.map_err(|error| Box::new(error) as Box<dyn std::error::Error>),
                Err(_) => Err(Box::<dyn std::error::Error>::from("relay graceful shutdown exceeded its configured budget")),
            }
        }
    };
    cleanup.abort();
    relay.close().await;
    result?;
    Ok(())
}

struct FixedClock(DateTime<Utc>);

impl RelayClock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await.expect("shutdown handler");
}

fn optional(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn required(name: &str) -> Result<String, String> {
    optional(name).ok_or_else(|| format!("{name} is required"))
}

fn integer(name: &str, default: i64) -> Result<i64, String> {
    let value = optional(name)
        .map(|value| {
            value
                .parse::<i64>()
                .map_err(|_| format!("{name} must be a positive integer"))
        })
        .transpose()?
        .unwrap_or(default);
    if value <= 0 {
        return Err(format!("{name} must be a positive integer"));
    }
    Ok(value)
}
