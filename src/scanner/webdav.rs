//! The WebDAV detection itself: connect + authenticate + mount IPC$ (all in
//! `transport::`, copied from RustHound-CE), then CREATE the WebClient named
//! pipe and read the NTSTATUS. The pipe's presence is the whole signal.
//!
//! ```text
//! TCP 445 -> NEGOTIATE -> SESSION_SETUP -> TREE_CONNECT IPC$      transport/smb.rs
//!   CREATE "DAV RPC SERVICE"                                      scanner/webdav.rs
//!     STATUS_SUCCESS                -> IsWebClientRunning = true
//!     STATUS_OBJECT_NAME_NOT_FOUND -> IsWebClientRunning = false
//!     STATUS_ACCESS_DENIED         -> Collected = false, FailureReason set
//! ```
//!
//! Compared with LocalGroups-rs we stop one step earlier: no DCE/RPC bind and
//! no opnum, because we only need to know the pipe exists. Everything is
//! read-only: the CREATE only opens the pipe; no RPC is issued.

use std::net::IpAddr;
use std::time::Duration;

use log::{debug, trace};
use smb2_client::SmbError;

use crate::scanner::types::{classify, status, Outcome, PIPE_NAME, PIPE_NAME_DISPLAY};
use crate::transport::{self, AuthConfig};

/// Probe one host. Returns `(resolved address, outcome)`.
///
/// `host` is what the operator typed (FQDN or IP). Under Kerberos the FQDN is
/// also the SPN host, so an IP target is rejected up front with a clear reason
/// rather than failing deep in the TGS-REQ.
pub async fn probe_host(
    host: &str,
    domain: &str,
    user: &str,
    auth: &AuthConfig,
    timeout: Duration,
) -> (Option<String>, Outcome) {
    // Kerberos needs a name to build cifs/<host>; an IP cannot map to an SPN.
    if matches!(auth, AuthConfig::Kerberos { .. }) && host.parse::<IpAddr>().is_ok() {
        return (
            None,
            Outcome::Error(format!(
                "Kerberos target must be an FQDN (cifs/<host> SPN); '{host}' is an IP"
            )),
        );
    }

    // Best-effort resolution for the report's `address` field. smb2-client does
    // its own resolution for the actual connect, so a miss here is not fatal.
    let address = resolve(host).await;

    // `-u` is documented as user@domain.local; SMB wants the bare sAMAccountName
    // (the transport builds DOMAIN\user itself). Normalize via the shared helper.
    let smb_user = transport::smb::smb_user(user);

    let outcome = match tokio::time::timeout(timeout, run(host, domain, &smb_user, auth)).await {
        Ok(o) => o,
        Err(_) => Outcome::Unreachable(format!("{host}: timed out after {}s", timeout.as_secs())),
    };
    (address, outcome)
}

/// The actual exchange, run under the per-host timeout.
async fn run(host: &str, domain: &str, user: &str, auth: &AuthConfig) -> Outcome {
    // connect + SESSION_SETUP + tree-connect IPC$ (shared transport, all three
    // auth paths behave exactly as in RustHound-CE / LocalGroups-rs).
    let mut smb = match transport::connect_ipc_with(host, domain, user, auth).await {
        Ok(c) => {
            debug!("[{host}] IPC$ ready, probing {PIPE_NAME_DISPLAY}");
            c
        }
        Err(e) => return connect_error(host, &e),
    };

    // CREATE the WebClient pipe. Raw open_pipe (not the anyhow wrapper) so the
    // NTSTATUS survives for classify(): Ok => running, Status => the reason.
    trace!("[{host}] CREATE {PIPE_NAME_DISPLAY}");
    match smb.open_pipe(PIPE_NAME).await {
        Ok(_file_id) => classify(status::SUCCESS),
        Err(SmbError::Status(code, _)) => classify(code),
        Err(other) => Outcome::Error(format!("open {PIPE_NAME_DISPLAY}: {other}")),
    }
}

/// Map a `connect_ipc_with` failure onto an [`Outcome`]. The transport wraps the
/// typed SMB error in `anyhow` with a stable prefix (`connect:` / `auth…:` /
/// `tree connect…`), which is enough to pick the right bucket.
fn connect_error(host: &str, e: &anyhow::Error) -> Outcome {
    let msg = format!("{host}: {e}");
    let s = e.to_string();
    if s.starts_with("auth") {
        Outcome::AuthFailed(msg)
    } else if s.starts_with("connect:") {
        Outcome::Unreachable(msg)
    } else if s.contains("tree connect") {
        // IPC$ refused: usually a hardened host, not a credential problem.
        Outcome::AccessDenied(msg)
    } else {
        Outcome::Error(msg)
    }
}

/// Best-effort async DNS/`:445` resolution for the report's address column.
async fn resolve(host: &str) -> Option<String> {
    match tokio::net::lookup_host(format!("{host}:445")).await {
        Ok(mut it) => it.next().map(|sa| sa.ip().to_string()),
        Err(_) => None,
    }
}
