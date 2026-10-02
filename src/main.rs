//! iswebclientrunning-rs - WebClient/WebDAV service probe (`IsWebClientRunning`) for
//! BloodHound Community Edition.
//!
//! A host running the WebClient service exposes `\PIPE\DAV RPC SERVICE` over SMB
//! and can be coerced to authenticate over HTTP, the prerequisite for ESC8
//! (ADCS web-enrollment) NTLM relaying and other coercion paths. This tool
//! sweeps a target scope and reports which hosts qualify, in BloodHound-shaped
//! JSON that maps onto RustHound-CE's `Computer` object.
//!
//! Layout:
//!   args.rs      CLI options, resolved into `Options`
//!   logger.rs    env_logger setup (INFO / -v DEBUG / -vv TRACE), copied style
//!   pace.rs      jitter PRNG + target shuffle
//!   targets.rs   scope expansion (host / CIDR / range)
//!   report.rs    the report shape and its renderings
//!   scanner/     the scan: types, the WebDAV probe, orchestration + validation
//!   transport/   SMB + Kerberos + GSS, copied verbatim from RustHound-CE
//!
//! Logs go to stderr, the report to stdout. Authorized use only.

mod args;
mod logger;
mod pace;
mod report;
mod scanner;
mod targets;
mod transport;

use anyhow::{Context, Result};
use colored::Colorize;
use log::{error, info, warn};

use args::{extract_args, Options, OutputFormat};
use report::Report;

#[tokio::main]
async fn main() -> Result<()> {
    let opts = extract_args();
    logger::init(opts.verbose, opts.quiet);

    settings(&opts);
    for w in &opts.scope_warnings {
        warn!("target skipped: {w}");
    }

    // Credential pre-check: one SESSION_SETUP against a DC so a typo in the
    // domain/username/secret fails here instead of locking the account out
    // across every target. Skipped with --no-validation.
    if opts.no_validation {
        warn!("credential pre-check skipped (--no-validation)");
    } else if let Err(e) = scanner::validate_credentials(&opts).await {
        error!("{e}");
        std::process::exit(2);
    }

    // Scan.
    let results = scanner::run(&opts).await;
    let report = Report::build(opts.domain.clone(), results);
    info!(
        "done: {} of {} host(s) running WebClient",
        report.running_count.to_string().bold(),
        report.hosts_scanned.len()
    );

    emit(&report, &opts)
}

/// Echo the run settings before scanning (INFO level).
fn settings(opts: &Options) {
    info!("Domain      : {}", opts.domain.bold());
    info!("User        : {}", opts.username.bold());
    info!("Auth        : {}", opts.auth.label().bold());
    info!("Targets     : {}", opts.targets.len());
    info!(
        "Workers     : {}{}",
        opts.workers,
        if opts.opsec { "  (opsec)" } else { "" }
    );
    if let Some((lo, hi)) = opts.jitter {
        info!("Jitter      : {lo}-{hi} ms");
    }
    if opts.shuffle {
        info!("Order       : shuffled");
    }
    info!("Timeout     : {}s", opts.timeout);
}

/// Render and deliver the report.
fn emit(report: &Report, opts: &Options) -> Result<()> {
    // Pipe-friendly stdout list modes short-circuit everything else.
    if opts.running_only {
        for h in &report.running {
            println!("{h}");
        }
        return Ok(());
    }
    if opts.status {
        for line in report.status_lines(opts.all) {
            println!("{line}");
        }
        return Ok(());
    }

    // stdout defaults to the table, a file defaults to JSON (one is read by a
    // person, the other by a tool). An explicit --table/--json/--compact wins.
    let format = match (&opts.output, opts.format_explicit) {
        (Some(_), false) => OutputFormat::Json,
        _ => opts.format.clone(),
    };

    // A table written to a file would carry ANSI escapes (colored only checks
    // whether stdout is a tty, not where we actually write).
    if opts.output.is_some() && matches!(format, OutputFormat::Table) {
        colored::control::set_override(false);
    }

    let rendered = match format {
        OutputFormat::Table => report.render_table(opts.all),
        OutputFormat::Json => report.to_json(false),
        OutputFormat::Compact => report.to_json(true),
    };

    match &opts.output {
        Some(dir) => {
            let path = output_path(dir, &opts.domain, &format);
            if let Some(parent) = std::path::Path::new(&path).parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            std::fs::write(&path, &rendered).with_context(|| format!("writing to {path}"))?;
            info!("{} created!", path.bold());
        }
        None => println!("{rendered}"),
    }
    Ok(())
}

/// `<dir>/<datetime>_<domain>_iswebclientrunning.<ext>`, the RustHound-CE naming scheme. The
/// extension follows the format: a `--table` run holds text, not JSON.
fn output_path(dir: &str, domain: &str, format: &OutputFormat) -> String {
    let datetime = chrono::Local::now().format("%Y%m%d%H%M%S").to_string();
    let domain = domain.to_lowercase();
    let ext = match format {
        OutputFormat::Table => "txt",
        _ => "json",
    };
    format!("{}/{datetime}_{domain}_iswebclientrunning.{ext}", dir.trim_end_matches('/'))
}