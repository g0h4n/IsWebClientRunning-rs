# Roadmap

What IsWebClientRunning-rs does today, and what is left. The target is parity with the
WebClient/WebDAV service check SharpHound and [Hackndo's `webclientservicescanner`](https://github.com/Hackndo/WebclientServiceScanner)
perform, in pure Rust, so the collection can move into [RustHound-CE](https://github.com/g0h4n/RustHound-CE)
as the `Computer`:`IsWebClientRunning` property.

## Done

- [x] WebClient detection by opening `\PIPE\DAV RPC SERVICE` over SMB `IPC$`, read-only :white_check_mark:
- [x] NTSTATUS classification: running / stopped / access-denied / unreachable / auth-failed :white_check_mark:
- [x] Three auth paths: password, pass-the-hash, Kerberos ccache (real `picky-krb` AP-REQ) :white_check_mark:
- [x] `src/transport/` copied verbatim from RustHound-CE / LocalGroups-rs, no system GSSAPI :white_check_mark:
- [x] Credential pre-validation against a DC, with `--dc` and `--no-validation` :white_check_mark:
- [x] Target scope: single host, IP, CIDR, last-octet range, full range, with `--max-expand` guard :white_check_mark:
- [x] Concurrency (`--workers`) and pacing (`--jitter`, `--shuffle`, `--opsec`) :white_check_mark:
- [x] BloodHound `Computer`-shaped output (`IsWebClientRunning` / `Collected` / `FailureReason`), table / JSON / compact :white_check_mark:
- [x] Pipe-friendly `--status` and `--running-only` stdout modes :white_check_mark:
- [x] Offline unit tests (classify, scope expansion, pacing PRNG, NT-hash parser) :white_check_mark:

## Next

- [ ] Resolve each running host's FQDN/SPN for direct hand-off to a coercion tool :red_circle: