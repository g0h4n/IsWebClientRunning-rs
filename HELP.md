<hr />

- [How to compile it?](#how-to-compile-it)
  - [Using Cargo](#using-cargo)
  - [Required dependencies](#required-dependencies)
- [Authentication](#authentication)
  - [Password bind](#password-bind)
  - [Pass-the-hash](#pass-the-hash)
  - [Kerberos pass-the-ticket](#kerberos-pass-the-ticket)
- [Credential validation](#credential-validation)
- [Targets and scope](#targets-and-scope)
- [Pacing and OPSEC](#pacing-and-opsec)
- [Options](#options)
- [What it detects](#what-it-detects)
- [Privileges required](#privileges-required)
- [Output](#output)
- [Verbosity](#verbosity)
- [Troubleshooting](#troubleshooting)

<hr />

# How to compile it?

## Using Cargo

```bash
cargo build --release
# Binary: ./target/release/iswebclientrunning-rs
./target/release/iswebclientrunning-rs -h
```

```bash
cargo test
```

The tests need no Domain Controller: the NTSTATUS `classify()`, the target-scope
expander (host / CIDR / range), the pacing PRNG and the NT-hash parser are all
exercised offline.

## Required dependencies

A recent Rust toolchain (edition 2021, **Rust >= 1.85** for the current crate
ecosystem). No system libraries are required at runtime: SMB2 and Kerberos are
pure Rust. In particular there is **no system GSSAPI dependency**, the ccache is
parsed in-crate and the AP-REQ built with `picky-krb`.

<hr />

# Authentication

The three paths are mutually exclusive: pick exactly one of `-p`, `-H`, `-k`.
They behave identically to RustHound-CE because `src/transport/` is the same code.

## Password bind

```bash
iswebclientrunning-rs -d ESSOS.LOCAL -u daenerys.targaryen -p 'P@ssw0rd!' -t MEEREEN.ESSOS.LOCAL
```

NTLMv2 SESSION_SETUP. The password is only used to compute the NTLMv2 response;
it never crosses the wire in clear.

## Pass-the-hash

```bash
iswebclientrunning-rs -d ESSOS.LOCAL -u daenerys.targaryen -H :34534854d33b398b66684072224bb47a -t BRAAVOS.ESSOS.LOCAL
```

The raw NT hash is plugged into the NTLMv2 step. Three input forms are accepted,
as in RustHound-CE:

```text
NTHASH                  32 hex chars
:NTHASH                 colon prefix, LM part empty
LMHASH:NTHASH           full pair, the LM part is ignored
```

## Kerberos pass-the-ticket

```bash
export KRB5CCNAME=/tmp/daenerys.targaryen.ccache
iswebclientrunning-rs -d ESSOS.LOCAL -u daenerys.targaryen -k -t MEEREEN.ESSOS.LOCAL

# Pin a specific KDC when the domain name does not resolve locally
iswebclientrunning-rs -d ESSOS.LOCAL -u daenerys.targaryen -k --kdc 192.168.56.12 -t MEEREEN.ESSOS.LOCAL
```

The TGT is read from the MIT ccache in `KRB5CCNAME`, a `cifs/<host>` service
ticket is requested, and a SPNEGO AP-REQ plus the 16-byte SMB session key are
handed to `SmbClient::login_kerberos`.

Two consequences worth knowing:

- The AP-REQ is bound to one host's SPN, so **Kerberos material is rebuilt for
  every target** in the scope. A wide sweep means one TGS-REQ per host.
- Targets must be named by the **FQDN the SPN uses**, not by IP. `-t 192.168.56.12 -k`
  is rejected up front with a clear reason rather than failing deep in the TGS-REQ.

Only lengths, etypes, realm and SPN are logged. Session keys, subkeys and ticket
bytes never are, at any verbosity.

<hr />

# Credential validation

Before probing a single target, the credentials are tested **once** against a
domain controller with a lone SMB `SESSION_SETUP`. This is a lockout guard: a
typo in `-d` / `-u` / `-p` / `-H` otherwise replays a bad credential at every
host in the scope and can trip the account lockout policy within one sweep.

```text
valid credentials      -> one INFO line, the scan proceeds
wrong credentials      -> the run aborts before any target is touched
DC unreachable/refused -> a WARN, the scan proceeds (not a credential fault)
```

The DC is chosen as `--dc` if given, else the `--kdc` under Kerberos, else the
`--domain` value (which resolves to a DC on a joined or DNS-pointed host). Skip
the check entirely with `--no-validation`.

```bash
# Point the check at a specific DC
iswebclientrunning-rs -d ESSOS.LOCAL -u daenerys -p 'BurnThemAll!' --dc DC01.ESSOS.LOCAL -t 10.0.0.0/24

# Skip it (you accept the lockout risk)
iswebclientrunning-rs -d ESSOS.LOCAL -u daenerys -p 'BurnThemAll!' --no-validation -t 10.0.0.0/24
```

<hr />

# Targets and scope

`-t` takes a comma-separated list and `-T` a file (one entry per line, `#`
comments ignored); the two are merged, de-duplicated, and order is preserved.
Each entry may be any of:

```text
host              MEEREEN.ESSOS.LOCAL        a single FQDN
ip                10.0.0.10                  a single IP
cidr              10.0.0.0/24                every address in the block
last-octet range  10.0.0.10-20               10.0.0.10 .. 10.0.0.20
full range        10.0.0.250-10.0.1.5        across octet boundaries
```

A single CIDR/range that would expand past `--max-expand` (default 65536) is
refused with a warning rather than silently eating memory; the rest of the scope
still runs.

<hr />

# Pacing and OPSEC

A WebClient sweep is a burst of short SMB sessions, which is noisy. Three knobs
shape the cadence:

```text
--workers N     hosts probed concurrently (default 32). Lower = quieter
--jitter MS     random pause between probes: "500" (0-500ms) or "200-800"
--shuffle       randomise target order so the sweep is not a linear subnet walk
--opsec         low-and-slow preset: --workers 1, --shuffle, --jitter 750-2500
```

`--opsec` is the one-flag "stay quiet" mode; `--jitter` given alongside it
overrides the default pause.

<hr />

# Options

```text
WebClient/WebDAV service probe (IsWebClientRunning) for BloodHound Community Edition.

g0h4n <https://twitter.com/g0h4n_0>

Usage: iswebclientrunning-rs [OPTIONS] --domain <DOMAIN> --username <USERNAME>

Options:
  -q, --quiet    Silence every log line so that stdout carries only the report
  -v...          Set the level of verbosity (-v debug, -vv trace)
  -h, --help     Print help (see more with '--help')
  -V, --version  Print version

Authentication:
  -d, --domain <DOMAIN>      Domain name like: DOMAIN.LOCAL
  -u, --username <USERNAME>  Username for the SMB session, like: user@domain.local
  -p, --password <PASSWORD>  Password for the SMB session
  -H, --hashes <HASHES>      NT hash for pass-the-hash authentication (NTLM), accept [NTHASH, :NTHASH, LMHASH:NTHASH]
  -k, --kerberos             Use Kerberos authentication. Grabs credentials from ccache (KRB5CCNAME) based on target parameters for Linux
      --kdc <KDC>            KDC to request the cifs/<host> tickets from, only used with --kerberos [default: the domain]
      --dc <DC>              Domain controller to test the credentials against before scanning [default: the --kdc for -k, else the domain]
      --no-validation        Skip the pre-scan credential check against a domain controller

Scan options:
  -t, --targets <TARGETS>            Target host(s), comma-separated. Each may be an FQDN, an IP, a CIDR (192.168.1.0/24) or a range (192.168.1.0-254)
  -T, --targets-file <TARGETS_FILE>  File containing one target per line, '#' lines are ignored. Each line may itself be an FQDN, IP, CIDR or range
      --timeout <TIMEOUT>            TCP connection timeout per host in seconds [default: 5]
      --workers <WORKERS>            Number of hosts probed concurrently (thread limit). Raise for a fast sweep, lower to stay quiet; --opsec forces this to 1 [default: 32]
      --jitter <JITTER>              Random pause between probes, in milliseconds, to break a constant cadence. Either a ceiling "500" (0-500ms) or a range "200-800". Applied per worker
      --shuffle                      Randomise the order targets are probed in (avoids a linear subnet sweep)
      --opsec                        Low-and-slow mode: forces one worker, shuffles targets and adds a random pause between every probe (default 750-2500ms unless --jitter is given)
      --max-expand <MAX_EXPAND>      Refuse any single CIDR/range spec that expands to more than this many hosts [default: 65536]

Output:
  -o, --output <OUTPUT>  Output directory for the report, named <datetime>_<domain>_iswebclientrunning.json (JSON unless --table) [default: stdout]
      --table            Print a colored, rounded result table [default] [alias: --pretty]
      --json             Print the JSON report instead of the table
      --compact          Print the JSON report on a single line
      --running-only     Only print the hosts where WebClient is running, one per line (pipe-friendly)
      --status           Print one line per target with its verdict (running / stopped / unknown), tab-separated and pipe-friendly
      --all              Show every target in the table / --status output, including hosts that did not respond. By default only hosts that answered the SMB probe are listed
```

`-p`, `-H` and `-k` are declared as conflicting in clap, so passing two of them
is rejected with a usage error. `--kdc` without `-k` is rejected too.

With `-o`, the file is named the way RustHound-CE names its own, so the two sit
side by side in the same loot directory:

```text
<dir>/<YYYYMMDDHHMMSS>_<domain>_iswebclientrunning.json
/tmp/loot/20260928112823_essos.local_iswebclientrunning.json
```

A `--table` run to `-o` is written as `.txt` (it holds text, not JSON) with the
ANSI colors stripped. Without `-o` the report goes to stdout.

<hr />

# What it detects

Everything is read-only. The per-host sequence is:

```text
TCP 445 -> NEGOTIATE -> SESSION_SETUP -> TREE_CONNECT IPC$      transport/smb.rs
  CREATE "DAV RPC SERVICE"                                      scanner/webdav.rs
    STATUS_SUCCESS                -> IsWebClientRunning = true
    STATUS_OBJECT_NAME_NOT_FOUND -> IsWebClientRunning = false
    STATUS_ACCESS_DENIED         -> Collected = false, FailureReason set
```

Compared with LocalGroups-rs the probe stops one step earlier: no DCE/RPC bind
and no opnum, because the pipe's existence is the entire signal. A host whose
WebClient is running can be coerced to authenticate over HTTP (PetitPotam,
PrinterBug, the `Coerce*` family) and relayed to AD CS web enrollment (ESC8).

<hr />

# Privileges required

Opening `IPC$` and the `DAV RPC SERVICE` pipe needs an **authenticated** SMB
session; any valid domain account is normally enough, no local admin on the
target is required. The service is not installed by default on servers (it is
the "WebClient" service, present and often running on workstations, and pulled
in by features like the Desktop Experience). Nothing is fatal: a host refused at
`SESSION_SETUP` or at the pipe is reported with `"Collected": false` and a
`FailureReason`, and the scan continues.

<hr />

# Output

The default is a colored, rounded table. `--json` is pretty JSON, `--compact`
is one line. The JSON `computers[]` entries use RustHound-CE's `Computer` field
casing (`IsWebClientRunning`, `Collected`, `FailureReason`) so the port is a
field map:

```json
{
  "domain": "ESSOS.LOCAL",
  "pipe": "\\PIPE\\DAV RPC SERVICE",
  "hosts_scanned": ["MEEREEN.ESSOS.LOCAL"],
  "running_count": 1,
  "running": ["MEEREEN.ESSOS.LOCAL"],
  "computers": [
    {
      "host": "MEEREEN.ESSOS.LOCAL",
      "address": "10.0.0.10",
      "IsWebClientRunning": true,
      "Collected": true,
      "FailureReason": null,
      "status": "STATUS_SUCCESS"
    }
  ]
}
```

Two terse stdout modes feed other tooling directly:

```bash
# only the hosts worth coercing, one per line
iswebclientrunning-rs ... --running-only | tee webdav_targets.txt

# host<TAB>verdict for every target (running / stopped / unknown)
iswebclientrunning-rs ... --status
```

<hr />

# Verbosity

Logs go to stderr, the report to stdout, so the two never mix in a pipe.

```text
(none)  INFO   settings, credential-check result, per running host, final tally
-v      DEBUG  per-host progress, IPC$/pipe steps, output size
-vv     TRACE  SMB negotiate/session-setup detail, Kerberos SPN/etype (no secrets)
-q      OFF    nothing on stderr at all
```