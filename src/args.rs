//! Command line surface, resolved into [`Options`].
//!
//! Modeled on RustHound-CE / LocalGroups-rs: the same auth trio (`-p` / `-H` /
//! `-k`), the same `-t` / `-T` targets and `-o` output naming. The raw clap
//! struct is turned into an [`Options`] that already carries the resolved
//! [`AuthConfig`], the expanded target scope and the pacing knobs, so the rest
//! of the program never re-parses anything.

use clap::{ArgAction, Parser};
use log::LevelFilter;

use crate::transport::AuthConfig;

/// Output rendering, chosen by `table` (default) / `json` / `compact`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Table,
    Json,
    Compact,
}

/// Raw command line, as parsed by clap.
#[derive(Parser, Debug)]
#[command(
    name = "iswebclientrunning-rs",
    author = "g0h4n <https://twitter.com/g0h4n_0>",
    version,
    about = "WebClient/WebDAV service probe (IsWebClientRunning) for BloodHound Community Edition.",
    long_about = "Probe one or more hosts for a running WebClient (WebDAV) service by opening the \
                  \\PIPE\\DAV RPC SERVICE named pipe over SMB. A host that answers is a candidate \
                  for authentication coercion to HTTP and therefore for ESC8 relaying.\n\n\
                  g0h4n <https://twitter.com/g0h4n_0>"
)]
pub struct Args {
    // ===================== Authentication =====================
    /// Domain name like: DOMAIN.LOCAL
    #[arg(short = 'd', long = "domain", help_heading = "Authentication")]
    pub domain: String,

    /// Username for the SMB session, like: user@domain.local
    #[arg(short = 'u', long = "username", help_heading = "Authentication")]
    pub username: String,

    /// Password for the SMB session
    #[arg(short = 'p', long = "password", conflicts_with_all = ["hashes", "kerberos"], help_heading = "Authentication")]
    pub password: Option<String>,

    /// NT hash for pass-the-hash authentication (NTLM), accept [NTHASH, :NTHASH, LMHASH:NTHASH]
    #[arg(short = 'H', long = "hashes", conflicts_with_all = ["password", "kerberos"], help_heading = "Authentication")]
    pub hashes: Option<String>,

    /// Use Kerberos authentication. Grabs credentials from ccache (KRB5CCNAME) based on target parameters for Linux.
    #[arg(short = 'k', long = "kerberos", help_heading = "Authentication")]
    pub kerberos: bool,

    /// KDC to request the cifs/<host> tickets from, only used with kerberos [default: the domain]
    #[arg(long = "kdc", help_heading = "Authentication")]
    pub kdc: Option<String>,

    /// Domain controller to test the credentials against before scanning
    /// [default: the kdc for -k, else the domain]
    #[arg(long = "dc", help_heading = "Authentication")]
    pub dc: Option<String>,

    /// Skip the pre-scan credential check against a domain controller
    #[arg(long = "no-validation", help_heading = "Authentication")]
    pub no_validation: bool,

    // ===================== Scan options =====================
    /// Target host(s), comma-separated. Each may be an FQDN, an IP, a CIDR
    /// (192.168.1.0/24) or a range (192.168.1.0-254)
    #[arg(short = 't', long = "targets", help_heading = "Scan options")]
    pub targets: Option<String>,

    /// File containing one target per line, '#' lines are ignored. Each line may
    /// itself be an FQDN, IP, CIDR or range
    #[arg(short = 'T', long = "targets-file", help_heading = "Scan options")]
    pub targets_file: Option<String>,

    /// TCP connection timeout per host in seconds
    #[arg(long = "timeout", default_value_t = 5, help_heading = "Scan options")]
    pub timeout: u64,

    /// Number of hosts probed concurrently (thread limit). Raise for a fast
    /// sweep, lower to stay quiet; opsec forces this to 1
    #[arg(long = "workers", default_value_t = 32, help_heading = "Scan options")]
    pub workers: usize,

    /// Random pause between probes, in milliseconds, to break a constant cadence.
    /// Either a ceiling "500" (0-500ms) or a range "200-800". Applied per worker
    #[arg(long = "jitter", help_heading = "Scan options")]
    pub jitter: Option<String>,

    /// Randomise the order targets are probed in (avoids a linear subnet sweep)
    #[arg(long = "shuffle", help_heading = "Scan options")]
    pub shuffle: bool,

    /// Low-and-slow mode: forces one worker, shuffles targets and adds a random
    /// pause between every probe (default 750-2500ms unless jitter is given)
    #[arg(long = "opsec", help_heading = "Scan options")]
    pub opsec: bool,

    /// Refuse any single CIDR/range spec that expands to more than this many hosts
    #[arg(long = "max-expand", default_value_t = crate::targets::DEFAULT_MAX_EXPAND, help_heading = "Scan options")]
    pub max_expand: u64,

    /// Output directory for the report, named <datetime>_<domain>_iswebclientrunning.json (JSON unless table) [default: stdout]
    #[arg(short = 'o', long = "output", help_heading = "Output")]
    pub output: Option<String>,

    /// Print a colored, rounded result table [default]
    #[arg(long = "table", visible_alias = "pretty", conflicts_with_all = ["json", "compact"], help_heading = "Output")]
    pub table: bool,

    /// Print the JSON report instead of the table
    #[arg(long = "json", conflicts_with = "compact", help_heading = "Output")]
    pub json: bool,

    /// Print the JSON report on a single line
    #[arg(long = "compact", help_heading = "Output")]
    pub compact: bool,

    /// Only print the hosts where WebClient is running, one per line (pipe-friendly)
    #[arg(long = "running-only", help_heading = "Output")]
    pub running_only: bool,

    /// Print one line per target with its verdict (running / stopped / unknown),
    /// tab-separated and pipe-friendly
    #[arg(long = "status", help_heading = "Output")]
    pub status: bool,

    /// Show every target in the table / status output, including hosts that did
    /// not respond. By default only hosts that answered the SMB probe are listed
    #[arg(long = "all", help_heading = "Output")]
    pub all: bool,

    // ===================== Options (logging / help) =====================
    /// Silence every log line so that stdout carries only the report
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    /// Set the level of verbosity (-v debug, -vv trace)
    #[arg(short = 'v', action = ArgAction::Count)]
    pub verbose: u8,
}

/// Fully resolved runtime options.
#[derive(Clone, Debug)]
pub struct Options {
    pub domain: String,
    pub username: String,
    pub auth: AuthConfig,
    pub targets: Vec<String>,
    /// Non-fatal target-expansion warnings, surfaced after the logger is up.
    pub scope_warnings: Vec<String>,

    pub timeout: u64,
    pub workers: usize,
    pub jitter: Option<(u64, u64)>,
    pub shuffle: bool,
    pub opsec: bool,

    pub output: Option<String>,
    pub format: OutputFormat,
    pub format_explicit: bool,
    pub running_only: bool,
    pub status: bool,
    pub all: bool,

    pub no_validation: bool,
    pub dc: Option<String>,

    pub verbose: LevelFilter,
    pub quiet: bool,
}

/// Parse the command line and resolve it, or exit with a clear message.
pub fn extract_args() -> Options {
    Args::parse().resolve().unwrap_or_else(|e| {
        eprintln!("[!] {e}");
        std::process::exit(2);
    })
}

impl Args {
    /// Turn the raw CLI into [`Options`]: build the auth config, expand the
    /// target scope, and resolve the pacing knobs.
    pub fn resolve(self) -> Result<Options, String> {
        //  targets -
        if self.targets.is_none() && self.targets_file.is_none() {
            return Err("no targets given: use -t and/or -T".into());
        }
        let inline: Vec<String> = self.targets.clone().into_iter().collect();
        let file_lines = match &self.targets_file {
            Some(path) => std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read targets file '{path}': {e}"))?
                .lines()
                .map(|l| l.to_string())
                .collect(),
            None => Vec::new(),
        };
        let (targets, scope_errors) =
            crate::targets::build_scope(&inline, &file_lines, self.max_expand);
        let scope_warnings: Vec<String> = scope_errors.iter().map(|e| e.to_string()).collect();
        if targets.is_empty() {
            return Err("no valid targets after expansion".into());
        }

        // auth 
        if self.kdc.is_some() && !self.kerberos {
            return Err("kdc is only meaningful together with -k/kerberos".into());
        }
        let auth = self.build_auth()?;

        // pacing 
        if self.workers == 0 {
            return Err("workers must be at least 1".into());
        }
        let (workers, jitter, shuffle) = self.effective_pacing()?;

        // output / format 
        let format = if self.compact {
            OutputFormat::Compact
        } else if self.json {
            OutputFormat::Json
        } else {
            OutputFormat::Table
        };
        let format_explicit = self.table || self.json || self.compact;

        let verbose = match self.verbose {
            0 => LevelFilter::Info,
            1 => LevelFilter::Debug,
            _ => LevelFilter::Trace,
        };

        Ok(Options {
            domain: self.domain,
            username: self.username,
            auth,
            targets,
            scope_warnings,
            timeout: self.timeout,
            workers,
            jitter,
            shuffle,
            opsec: self.opsec,
            output: self.output,
            format,
            format_explicit,
            running_only: self.running_only,
            status: self.status,
            all: self.all,
            no_validation: self.no_validation,
            dc: self.dc,
            verbose,
            quiet: self.quiet,
        })
    }

    /// Resolve exactly one of password / hash / Kerberos into an [`AuthConfig`].
    fn build_auth(&self) -> Result<AuthConfig, String> {
        if self.kerberos {
            // Pass-the-ticket: TGT from the ccache in KRB5CCNAME, a cifs/<host>
            // service ticket built per target at connect time.
            let ccache = match std::env::var("KRB5CCNAME") {
                Ok(v) if !v.trim().is_empty() => v,
                _ => {
                    return Err("kerberos requires KRB5CCNAME to point at an MIT ccache \
                                (e.g. export KRB5CCNAME=/tmp/user.ccache)"
                        .into())
                }
            };
            let path = ccache.strip_prefix("FILE:").unwrap_or(&ccache);
            if !std::path::Path::new(path).exists() {
                return Err(format!("ccache '{path}' (from KRB5CCNAME) does not exist"));
            }
            // No kdc: the domain name resolves to a DC on a joined/DNS-pointed host.
            let kdc = self.kdc.clone().unwrap_or_else(|| self.domain.clone());
            Ok(AuthConfig::Kerberos { ccache, kdc })
        } else if let Some(h) = &self.hashes {
            Ok(AuthConfig::Hash(parse_nt_hash(h)?))
        } else if let Some(p) = &self.password {
            Ok(AuthConfig::Password(p.clone()))
        } else {
            Err("no authentication given: use one of -p / -H / -k".into())
        }
    }

    /// Parse `jitter` into an inclusive `(min_ms, max_ms)`, or `None`. Accepts
    /// a ceiling (`"500"` -> `0..=500`) or a range (`"200-800"`).
    pub fn jitter_range(&self) -> Result<Option<(u64, u64)>, String> {
        let Some(spec) = self.jitter.as_deref() else {
            return Ok(None);
        };
        let spec = spec.trim();
        let (lo, hi) = match spec.split_once('-') {
            Some((a, b)) => (
                a.trim().parse().map_err(|_| bad_jitter(spec))?,
                b.trim().parse().map_err(|_| bad_jitter(spec))?,
            ),
            None => (0, spec.parse().map_err(|_| bad_jitter(spec))?),
        };
        if hi < lo {
            return Err(format!("jitter range is inverted: {lo} > {hi}"));
        }
        Ok(Some((lo, hi)))
    }

    /// Resolve pacing, applying `opsec`: one worker, shuffle, and a 750-2500ms
    /// pause unless `jitter` overrides it. Returns `(workers, jitter, shuffle)`.
    pub fn effective_pacing(&self) -> Result<(usize, Option<(u64, u64)>, bool), String> {
        let mut workers = self.workers;
        let mut jitter = self.jitter_range()?;
        let mut shuffle = self.shuffle;
        if self.opsec {
            workers = 1;
            shuffle = true;
            if jitter.is_none() {
                jitter = Some((750, 2500));
            }
        }
        Ok((workers, jitter, shuffle))
    }
}

fn bad_jitter(spec: &str) -> String {
    format!("invalid jitter '{spec}': use milliseconds, e.g. 500 or 200-800")
}

/// Parse an NT hash into 16 bytes. Accepted: `NTHASH`, `:NTHASH`,
/// `LMHASH:NTHASH` (the LM part is ignored). Mirrors RustHound-CE.
pub fn parse_nt_hash(input: &str) -> Result<[u8; 16], String> {
    let clean = input.trim();
    let nt = match clean.split_once(':') {
        Some((_lm, nt)) => nt,
        None => clean,
    };
    if nt.len() != 32 || !nt.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "invalid NT hash '{nt}': expected exactly 32 hex characters \
             (NTHASH | :NTHASH | LMHASH:NTHASH)"
        ));
    }
    let mut bytes = [0u8; 16];
    for (i, pair) in nt.as_bytes().chunks(2).enumerate() {
        bytes[i] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nt_hash_formats() {
        let nt = "31d6cfe0d16ae931b73c59d7e0c089c0";
        let want = [
            0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0,
            0x89, 0xc0,
        ];
        assert_eq!(parse_nt_hash(nt).unwrap(), want);
        assert_eq!(parse_nt_hash(&format!(":{nt}")).unwrap(), want);
        assert_eq!(parse_nt_hash(&format!("aad3b435b51404ee:{nt}")).unwrap(), want);
    }

    #[test]
    fn nt_hash_rejects_bad() {
        assert!(parse_nt_hash("xyz").is_err());
        assert!(parse_nt_hash("31d6").is_err());
    }
}