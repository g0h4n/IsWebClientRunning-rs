//! The scan: validate the credentials once, then probe every target.
//!
//! * [`types`]   - the pipe name, NTSTATUS values and the [`Outcome`] verdict.
//! * [`webdav`]  - the per-host WebDAV probe over the shared `transport::`.
//! * this file   - concurrency (a `--workers` semaphore), pacing (`--jitter` /
//!                 `--opsec` shuffle) and the pre-scan credential check.

pub mod types;
pub mod webdav;

use std::io::IsTerminal;
use std::sync::Arc;
use std::time::Duration;

use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, error, info, warn, LevelFilter};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::args::Options;
use crate::pace::{self, Rng};
use crate::report::HostResult;
use crate::transport::{self, AuthConfig};

/// Test the provided credentials against a domain controller before the sweep.
///
/// A single SESSION_SETUP, not one per host: if the domain/username/password is
/// wrong, we find out now instead of failing auth on every target and burning
/// the account's lockout counter. Returns `Err` only on an authentication
/// failure (caller should abort); a connectivity failure is reported as `Ok`
/// with a warning, since it is not a credential problem and must not block a
/// scan of reachable targets.
pub async fn validate_credentials(opts: &Options) -> Result<(), String> {
    let dc = validation_target(opts);
    let user = transport::smb::smb_user(&opts.username);
    info!(
        "Validating credentials ({}) against {} ...",
        opts.auth.label(),
        dc.bold()
    );

    let fut = transport::connect_ipc_with(&dc, &opts.domain, &user, &opts.auth);
    match tokio::time::timeout(Duration::from_secs(opts.timeout), fut).await {
        Ok(Ok(_smb)) => {
            info!("Credentials valid for {}\\{}", opts.domain, user);
            Ok(())
        }
        Ok(Err(e)) => {
            let s = e.to_string();
            if s.starts_with("auth") {
                // Wrong credentials: stop before we touch any target.
                Err(format!(
                    "credential check failed against {dc}: {e}. \
                     Fix the domain/username/secret, or pass --no-validation to skip this check."
                ))
            } else {
                // Could not reach / tree-connect the DC: not a credential fault.
                warn!(
                    "could not validate credentials against {dc} ({e}); \
                     proceeding without pre-check (use --dc to point at a reachable DC)"
                );
                Ok(())
            }
        }
        Err(_) => {
            warn!(
                "credential check against {dc} timed out after {}s; proceeding without pre-check",
                opts.timeout
            );
            Ok(())
        }
    }
}

/// Which host to run the credential check against: an explicit `--dc`, else the
/// KDC for Kerberos, else the domain name (which resolves to a DC on a joined or
/// DNS-pointed host).
fn validation_target(opts: &Options) -> String {
    if let Some(dc) = &opts.dc {
        return dc.clone();
    }
    match &opts.auth {
        AuthConfig::Kerberos { kdc, .. } => kdc.clone(),
        _ => opts.domain.clone(),
    }
}

/// Probe every target and return one [`HostResult`] per host, in scan order.
pub async fn run(opts: &Options) -> Vec<HostResult> {
    // Target order: shuffled for --opsec / --shuffle so the sweep is not linear.
    let mut targets = opts.targets.clone();
    if opts.shuffle {
        let mut rng = Rng::from_time(0xA5A5_5A5A);
        pace::shuffle(&mut targets, &mut rng);
    }

    let total = targets.len();
    let timeout = Duration::from_secs(opts.timeout);
    let sem = Arc::new(Semaphore::new(opts.workers.max(1)));
    let mut set: JoinSet<(usize, HostResult)> = JoinSet::new();

    for (idx, host) in targets.into_iter().enumerate() {
        let sem = Arc::clone(&sem);
        let domain = opts.domain.clone();
        let username = opts.username.clone();
        let auth = opts.auth.clone();
        let jitter = opts.jitter;
        set.spawn(async move {
            // Hold a worker slot for the whole probe.
            let _permit = sem.acquire_owned().await.expect("semaphore open");
            let (address, outcome) =
                webdav::probe_host(&host, &domain, &username, &auth, timeout).await;

            // Pace the next connection on this worker (jitter / opsec).
            if let Some((lo, hi)) = jitter {
                let mut rng = Rng::from_time(idx as u64 + 1);
                tokio::time::sleep(Duration::from_millis(rng.range(lo, hi))).await;
            }

            (idx, HostResult::from_outcome(host, address, &outcome))
        });
    }

    // Progress bar, RustHound-CE style: a braille spinner plus a live [done/total]
    // counter, drawn on stderr so stdout stays clean. Shown only at the default
    // verbosity on a real terminal; with -v/-vv the per-host log lines take its
    // place, and it is hidden when quiet, piped, or for a single target.
    let pb = progress_bar(opts, total);

    // Collect, preserving scan order, and report each host as it lands.
    let mut slots: Vec<Option<HostResult>> = (0..total).map(|_| None).collect();
    let (mut running, mut alive) = (0usize, 0usize);
    while let Some(joined) = set.join_next().await {
        let (idx, result) = match joined {
            Ok(v) => v,
            Err(e) => {
                error!("probe task panicked: {e}");
                continue;
            }
        };
        if result.is_webclient_running {
            running += 1;
        }
        if result.alive {
            alive += 1;
        }
        match &pb {
            // With the bar up, running hosts are printed above it (clean redraw)
            // and the counts ride along in the message.
            Some(pb) => {
                pb.inc(1);
                if result.is_webclient_running {
                    pb.println(format!(
                        "  {}  {}",
                        result.host,
                        "WebClient RUNNING".green().bold()
                    ));
                }
                pb.set_message(format!("{running} running · {alive} alive"));
            }
            // No bar: fall back to the log lines (INFO for a hit, DEBUG otherwise).
            None => {
                if result.is_webclient_running {
                    info!("[{}] WebClient RUNNING", result.host);
                } else if result.collected {
                    debug!("[{}] stopped ({})", result.host, result.status);
                } else {
                    debug!("[{}] {}", result.host, result.status);
                }
            }
        }
        slots[idx] = Some(result);
    }
    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    slots.into_iter().flatten().collect()
}

/// Build the scan progress bar
fn progress_bar(opts: &Options, total: usize) -> Option<ProgressBar> {
    let wanted = opts.verbose == LevelFilter::Info
        && total > 1
        && std::io::stderr().is_terminal();
    if !wanted {
        return None;
    }
    let pb = ProgressBar::new(total as u64);
    pb.set_style(
        ProgressStyle::with_template("{prefix:.bold.dim} {spinner} [{pos}/{len}] {wide_msg}")
            .unwrap()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "),
    );
    pb.set_prefix("scan");
    pb.enable_steady_tick(Duration::from_millis(80));
    Some(pb)
}