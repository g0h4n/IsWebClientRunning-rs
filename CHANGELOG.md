# Changelog

## 0.1.0 - 2026-10-02

First release. Probes Windows hosts for a running **WebClient (WebDAV)** service
and reports it as the BloodHound `Computer`:`IsWebClientRunning` property, the
prerequisite for HTTP coercion and ESC8 relaying.

### Detection
- Opens `\PIPE\DAV RPC SERVICE` over SMB `IPC$`; the NTSTATUS is the verdict
  (`STATUS_SUCCESS` = running, `STATUS_OBJECT_NAME_NOT_FOUND` = stopped,
  `STATUS_ACCESS_DENIED` = not collected).
- Read-only: a single `CREATE`, no DCE/RPC bound, nothing written.

### Authentication
- Password (`-p`), pass-the-hash (`-H`), Kerberos pass-the-ticket (`-k`, ccache
  from `KRB5CCNAME`, `--kdc` to pin a DC).
- Real Kerberos (in-crate ccache parse, `picky-krb` AP-REQ); no system GSSAPI.
  Password/hash redacted in logs.
- `src/transport/{smb,gss,kerberos}.rs` copied verbatim from RustHound-CE.
- Credentials checked once against a DC before scanning (`--dc`, skip with
  `--no-validation`) to avoid locking out the account.

### Scanning
- Targets: host, IP, CIDR, range via `-t` / `-T` (merged, de-duplicated,
  `--max-expand` guard).
- Concurrency `--workers`, pacing `--jitter` / `--shuffle`, `--opsec` low-and-slow
  preset.
- RustHound-CE-style progress bar (hidden when quiet, piped or verbose).

### Output
- Colored table by default (alive hosts only; `--all` shows every target), `--json` / `--compact`, `-o <dir>` writes `<datetime>_<domain>_iswebclientrunning.{json,txt}`.
- `--status` and `--running-only` pipe-friendly modes.
- JSON uses RustHound-CE's `Computer` field casing (`IsWebClientRunning`, `Collected`, `FailureReason`) for a straight port.