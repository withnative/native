//! `mcp::fetch` — the SSRF-guarded fetch path behind tool 23
//! (`attach_from_url`). The guard is CONTRACT, not polish
//! (docs/tool-surface.md): an engine that fetches arbitrary URLs is a
//! local-network exfiltration surface without it.
//!
//! Five guarantees, each with tests (`tests/tools/fetch_guard.rs`):
//!   1. **Scheme allowlist** — http/https only, checked on every hop.
//!   2. **Address policy** — private / link-local / loopback / otherwise
//!      non-public addresses are rejected, whether written literally or
//!      resolved from a hostname ([`ip_rejection`]).
//!   3. **Pinned DNS** — each host is resolved ONCE, every resolved address
//!      is checked, and the connection is constrained to exactly those
//!      addresses (`reqwest`'s `resolve_to_addrs` override with redirects
//!      disabled). There is no second resolution between check and connect,
//!      so a DNS-rebinding attacker has no TOCTOU window to race.
//!   4. **Per-hop redirect revalidation** — redirects are DISABLED at the
//!      client (`redirect::Policy::none()`) and re-driven by the loop here,
//!      so every hop passes 1–3 afresh: a 302 into `169.254.169.254` fails
//!      exactly like a direct request to it.
//!   5. **Streamed size cap** — rejected early on a declared Content-Length,
//!      and enforced on the byte stream regardless of what was declared.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use reqwest::header::{CONTENT_TYPE, LOCATION};
use reqwest::redirect::Policy;
use url::{Host, Url};

use crate::error::{Error, Result};

/// Default per-fetch byte cap (tool 23 is `storage_tier='inline'` — the bytes
/// land in the database, so the default stays modest).
pub const DEFAULT_MAX_FETCH_BYTES: u64 = 5 * 1024 * 1024;
/// The hard ceiling a caller-supplied cap may not exceed.
pub const MAX_FETCH_BYTES: u64 = 20 * 1024 * 1024;
/// Default whole-request timeout, per hop.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// Default redirect-hop budget.
pub const DEFAULT_MAX_REDIRECTS: u32 = 5;

/// The DNS seam: hostname + port -> the addresses the fetch may connect to.
/// Injectable so the guard's own tests can serve DNS-rebinding scripts; the
/// default is [`system_resolver`].
pub type Resolver =
    Arc<dyn Fn(String, u16) -> BoxFuture<'static, Result<Vec<SocketAddr>>> + Send + Sync>;

/// The system resolver (`tokio::net::lookup_host`), called once per host.
pub fn system_resolver() -> Resolver {
    Arc::new(|host, port| {
        Box::pin(async move {
            let addrs = tokio::net::lookup_host((host.as_str(), port))
                .await
                .map_err(|e| Error::engine(format!("cannot resolve host '{host}': {e}")))?
                .collect();
            Ok(addrs)
        })
    })
}

/// Guarded-fetch policy knobs. [`FetchConfig::default`] is the production
/// posture; tests narrow caps and swap the resolver.
#[derive(Clone)]
pub struct FetchConfig {
    /// Streamed byte cap (guarantee 5).
    pub max_bytes: u64,
    /// Whole-request timeout, applied per hop.
    pub timeout: Duration,
    /// Redirect-hop budget (each hop revalidates from scratch).
    pub max_redirects: u32,
    /// TEST SEAM ONLY: permits *loopback* destinations so the guard's own
    /// tests can stand a server on 127.0.0.1. Every other rejection class
    /// (private, link-local, …) stays enforced regardless of this flag.
    pub allow_loopback: bool,
    /// The DNS seam (guarantee 3).
    pub resolver: Resolver,
}

impl Default for FetchConfig {
    fn default() -> Self {
        FetchConfig {
            max_bytes: DEFAULT_MAX_FETCH_BYTES,
            timeout: DEFAULT_TIMEOUT,
            max_redirects: DEFAULT_MAX_REDIRECTS,
            allow_loopback: false,
            resolver: system_resolver(),
        }
    }
}

/// A completed guarded fetch.
#[derive(Debug)]
pub struct Fetched {
    pub bytes: Vec<u8>,
    /// The response's Content-Type header, verbatim, if any.
    pub mime: Option<String>,
    /// The URL the bytes actually came from (after redirects).
    pub final_url: String,
    pub redirects: u32,
}

/// Why an IP address is not a permitted fetch destination — `None` means the
/// address is publicly routable and allowed. Guarantee 2, applied to literal
/// hosts and to every resolved address alike. `allow_loopback` is the test
/// seam described on [`FetchConfig`]; it exempts loopback ONLY.
pub fn ip_rejection(ip: IpAddr, allow_loopback: bool) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if v4.is_loopback() {
                if allow_loopback {
                    return None;
                }
                Some("loopback")
            } else if o[0] == 0 {
                Some("this-network (0.0.0.0/8)")
            } else if v4.is_private() {
                Some("private (RFC 1918)")
            } else if v4.is_link_local() {
                Some("link-local (169.254.0.0/16)")
            } else if o[0] == 100 && (o[1] & 0xc0) == 64 {
                Some("shared CGNAT (100.64.0.0/10)")
            } else if o[0] == 192 && o[1] == 0 && o[2] == 0 {
                Some("IETF protocol assignments (192.0.0.0/24)")
            } else if (o[0] == 192 && o[1] == 0 && o[2] == 2)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
            {
                Some("documentation range")
            } else if o[0] == 198 && (o[1] & 0xfe) == 18 {
                Some("benchmarking (198.18.0.0/15)")
            } else if v4.is_broadcast() {
                Some("broadcast")
            } else if v4.is_multicast() {
                Some("multicast")
            } else if o[0] >= 240 {
                Some("reserved (240.0.0.0/4)")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            // Embedded IPv4 first: mapped (::ffff:a.b.c.d) and NAT64
            // (64:ff9b::/96) both reach IPv4 space — judge the inner address.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return ip_rejection(IpAddr::V4(v4), allow_loopback);
            }
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                let v4 = std::net::Ipv4Addr::new(
                    (s[6] >> 8) as u8,
                    (s[6] & 0xff) as u8,
                    (s[7] >> 8) as u8,
                    (s[7] & 0xff) as u8,
                );
                return ip_rejection(IpAddr::V4(v4), allow_loopback);
            }
            if v6.is_loopback() {
                if allow_loopback {
                    return None;
                }
                Some("loopback")
            } else if v6.is_unspecified() {
                Some("unspecified (::)")
            } else if (s[0] & 0xfe00) == 0xfc00 {
                Some("unique-local (fc00::/7)")
            } else if (s[0] & 0xffc0) == 0xfe80 {
                Some("link-local (fe80::/10)")
            } else if (s[0] & 0xffc0) == 0xfec0 {
                Some("site-local (fec0::/10, deprecated)")
            } else if v6.is_multicast() {
                Some("multicast")
            } else if s[0] == 0x2001 && s[1] == 0x0db8 {
                Some("documentation (2001:db8::/32)")
            } else {
                None
            }
        }
    }
}

/// Fetch a URL under the full guard. Every redirect hop re-enters the same
/// loop, so schemes, addresses and DNS pins are revalidated per hop.
pub async fn fetch_url(raw_url: &str, config: &FetchConfig) -> Result<Fetched> {
    let mut url =
        Url::parse(raw_url).map_err(|e| Error::engine(format!("invalid url '{raw_url}': {e}")))?;
    let mut redirects = 0u32;
    loop {
        // Guarantee 1: scheme allowlist, every hop.
        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(Error::engine(format!(
                "scheme '{scheme}' is not allowed — only http and https URLs can be fetched"
            )));
        }
        let host = url
            .host()
            .ok_or_else(|| Error::engine(format!("url '{url}' has no host")))?;
        let port = url
            .port_or_known_default()
            .expect("http/https always have a known default port");

        let mut builder = reqwest::Client::builder()
            .redirect(Policy::none()) // guarantee 4: hops are re-driven here
            .timeout(config.timeout)
            .connect_timeout(config.timeout.min(Duration::from_secs(10)));
        match host {
            // Literal address: judge it directly (guarantee 2).
            Host::Ipv4(ip) => {
                if let Some(reason) = ip_rejection(IpAddr::V4(ip), config.allow_loopback) {
                    return Err(Error::engine(format!(
                        "refusing to fetch '{url}': address {ip} is {reason}"
                    )));
                }
            }
            Host::Ipv6(ip) => {
                if let Some(reason) = ip_rejection(IpAddr::V6(ip), config.allow_loopback) {
                    return Err(Error::engine(format!(
                        "refusing to fetch '{url}': address {ip} is {reason}"
                    )));
                }
            }
            // Hostname: resolve ONCE, judge every address, and pin the
            // connection to exactly the judged set (guarantees 2 + 3).
            Host::Domain(domain) => {
                let addrs = (config.resolver)(domain.to_string(), port).await?;
                if addrs.is_empty() {
                    return Err(Error::engine(format!(
                        "cannot resolve host '{domain}': no addresses"
                    )));
                }
                for addr in &addrs {
                    if let Some(reason) = ip_rejection(addr.ip(), config.allow_loopback) {
                        return Err(Error::engine(format!(
                            "refusing to fetch '{url}': host '{domain}' resolves to {} ({reason})",
                            addr.ip()
                        )));
                    }
                }
                builder = builder.resolve_to_addrs(domain, &addrs);
            }
        }
        let client = builder
            .build()
            .map_err(|e| Error::engine(format!("cannot build http client: {e}")))?;
        let response = client
            .get(url.clone())
            .send()
            .await
            .map_err(|e| Error::engine(format!("fetch of '{url}' failed: {e}")))?;

        let status = response.status();
        if status.is_redirection() {
            let Some(location) = response
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(String::from)
            else {
                return Err(Error::engine(format!(
                    "redirect from '{url}' carries no Location header"
                )));
            };
            redirects += 1;
            if redirects > config.max_redirects {
                return Err(Error::engine(format!(
                    "too many redirects fetching '{raw_url}' (limit {})",
                    config.max_redirects
                )));
            }
            url = url.join(&location).map_err(|e| {
                Error::engine(format!("invalid redirect location '{location}': {e}"))
            })?;
            continue; // the next hop re-runs the whole guard
        }
        if !status.is_success() {
            return Err(Error::engine(format!(
                "fetch of '{url}' failed with status {status}"
            )));
        }

        // Guarantee 5: reject early on a declared length…
        if let Some(declared) = response.content_length() {
            if declared > config.max_bytes {
                return Err(Error::engine(format!(
                    "response from '{url}' exceeds the {} byte cap (Content-Length {declared})",
                    config.max_bytes
                )));
            }
        }
        let mime = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        // …and enforce on the stream regardless of what was declared.
        let mut response = response;
        let mut bytes: Vec<u8> = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| Error::engine(format!("fetch of '{url}' failed mid-stream: {e}")))?
        {
            if bytes.len() as u64 + chunk.len() as u64 > config.max_bytes {
                return Err(Error::engine(format!(
                    "response from '{url}' exceeds the {} byte cap",
                    config.max_bytes
                )));
            }
            bytes.extend_from_slice(&chunk);
        }
        return Ok(Fetched {
            bytes,
            mime,
            final_url: url.to_string(),
            redirects,
        });
    }
}
