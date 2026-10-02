//! Target parsing and scope expansion.
//!
//! A *spec* is one token the operator typed on `-t` (comma separated) or one
//! non-comment line of the `-T` file. Four shapes are accepted:
//!
//! | Shape            | Example                        | Expands to                       |
//! | ---------------- | ------------------------------ | -------------------------------- |
//! | single host      | `DC01.ESSOS.LOCAL`, `10.0.0.5` | itself                           |
//! | IPv4 CIDR        | `192.168.1.0/24`               | every address in the block       |
//! | last-octet range | `192.168.1.0-254`              | `192.168.1.0` .. `192.168.1.254` |
//! | full IPv4 range  | `192.168.1.10-192.168.1.20`    | `192.168.1.10` .. `192.168.1.20` |
//!
//! FQDNs and hostnames are kept verbatim: a `-` inside a name
//! (`dc-01.essos.local`) is never mistaken for a range, because the part before
//! the `-` does not parse as an IPv4 address. Resolution to an address happens
//! later, at probe time, exactly as in `LocalGroups-rs`.
//!
//! Kerberos note: CIDR and range specs expand to bare IPs, and a `cifs/<host>`
//! SPN cannot be built from an IP. With `-k`, expanded IP targets are reported
//! per host as a Kerberos-incompatible failure; name your DCs by FQDN instead.

use std::collections::HashSet;
use std::fmt;
use std::net::Ipv4Addr;

/// Hard ceiling on how many addresses a single CIDR/range spec may expand to.
/// Stops `10.0.0.0/8` from turning into 16M probes by accident. Override with
/// `--max-expand`.
pub const DEFAULT_MAX_EXPAND: u64 = 65_536;

#[derive(Debug, PartialEq, Eq)]
pub enum TargetError {
    Empty,
    BadCidr(String),
    BadRange(String),
    RangeReversed(String),
    TooLarge { spec: String, count: u64, max: u64 },
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetError::Empty => write!(f, "empty target spec"),
            TargetError::BadCidr(s) => write!(f, "invalid CIDR: {s}"),
            TargetError::BadRange(s) => write!(f, "invalid range: {s}"),
            TargetError::RangeReversed(s) => write!(f, "range start is after end: {s}"),
            TargetError::TooLarge { spec, count, max } => write!(
                f,
                "spec '{spec}' expands to {count} hosts, above the {max} cap (raise it with --max-expand)"
            ),
        }
    }
}

impl std::error::Error for TargetError {}

/// Parse a single spec into one or more concrete host strings.
pub fn parse_spec(spec: &str, max_expand: u64) -> Result<Vec<String>, TargetError> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err(TargetError::Empty);
    }

    // CIDR: only when the left side is a real IPv4 address.
    if let Some((net, prefix)) = spec.split_once('/') {
        let base: Ipv4Addr = net
            .parse()
            .map_err(|_| TargetError::BadCidr(spec.to_string()))?;
        let prefix: u32 = prefix
            .parse()
            .map_err(|_| TargetError::BadCidr(spec.to_string()))?;
        if prefix > 32 {
            return Err(TargetError::BadCidr(spec.to_string()));
        }
        return expand_cidr(base, prefix, spec, max_expand);
    }

    // Range: only when the part before '-' is a real IPv4 address. This keeps
    // hostnames like `dc-01.essos.local` out of the range branch.
    if let Some((start_s, end_s)) = spec.split_once('-') {
        if let Ok(start) = start_s.parse::<Ipv4Addr>() {
            let end = if let Ok(full) = end_s.parse::<Ipv4Addr>() {
                full
            } else if let Ok(last) = end_s.parse::<u8>() {
                let o = start.octets();
                Ipv4Addr::new(o[0], o[1], o[2], last)
            } else {
                return Err(TargetError::BadRange(spec.to_string()));
            };
            return expand_range(start, end, spec, max_expand);
        }
        // else: a hostname that merely contains '-', fall through.
    }

    // Single host: IPv4 literal, IPv6 literal, or a name. Kept as typed.
    Ok(vec![spec.to_string()])
}

fn expand_cidr(
    base: Ipv4Addr,
    prefix: u32,
    spec: &str,
    max_expand: u64,
) -> Result<Vec<String>, TargetError> {
    let count: u64 = 1u64 << (32 - prefix);
    if count > max_expand {
        return Err(TargetError::TooLarge {
            spec: spec.to_string(),
            count,
            max: max_expand,
        });
    }
    let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let network = u32::from(base) & mask;
    let out = (0..count as u32)
        .map(|i| Ipv4Addr::from(network + i).to_string())
        .collect();
    Ok(out)
}

fn expand_range(
    start: Ipv4Addr,
    end: Ipv4Addr,
    spec: &str,
    max_expand: u64,
) -> Result<Vec<String>, TargetError> {
    let (s, e) = (u32::from(start), u32::from(end));
    if s > e {
        return Err(TargetError::RangeReversed(spec.to_string()));
    }
    let count = (e - s) as u64 + 1;
    if count > max_expand {
        return Err(TargetError::TooLarge {
            spec: spec.to_string(),
            count,
            max: max_expand,
        });
    }
    let out = (s..=e).map(|v| Ipv4Addr::from(v).to_string()).collect();
    Ok(out)
}

/// Merge every `-t` token and `-T` line into a de-duplicated, order-preserving
/// host list. Errors from a single spec are collected and returned alongside the
/// hosts so the caller can warn and keep going, matching the "nothing is fatal"
/// stance of the collectors.
pub fn build_scope(
    inline: &[String],
    file_lines: &[String],
    max_expand: u64,
) -> (Vec<String>, Vec<TargetError>) {
    let mut hosts = Vec::new();
    let mut seen = HashSet::new();
    let mut errors = Vec::new();

    let mut push = |spec: &str, errors: &mut Vec<TargetError>| match parse_spec(spec, max_expand) {
        Ok(expanded) => {
            for h in expanded {
                if seen.insert(h.clone()) {
                    hosts.push(h);
                }
            }
        }
        Err(e) => errors.push(e),
    };

    for token in inline {
        for spec in token.split(',') {
            let spec = spec.trim();
            if !spec.is_empty() {
                push(spec, &mut errors);
            }
        }
    }

    for line in file_lines {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // A file line may itself be a comma-list or a CIDR/range.
        for spec in line.split(',') {
            let spec = spec.trim();
            if !spec.is_empty() {
                push(spec, &mut errors);
            }
        }
    }

    (hosts, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: u64 = DEFAULT_MAX_EXPAND;

    #[test]
    fn single_ip() {
        assert_eq!(parse_spec("192.168.1.10", MAX).unwrap(), vec!["192.168.1.10"]);
    }

    #[test]
    fn single_fqdn() {
        assert_eq!(
            parse_spec("DC01.ESSOS.LOCAL", MAX).unwrap(),
            vec!["DC01.ESSOS.LOCAL"]
        );
    }

    #[test]
    fn hostname_with_dash_is_not_a_range() {
        assert_eq!(
            parse_spec("dc-01.essos.local", MAX).unwrap(),
            vec!["dc-01.essos.local"]
        );
    }

    #[test]
    fn cidr_24_has_256_addresses() {
        let v = parse_spec("192.168.1.0/24", MAX).unwrap();
        assert_eq!(v.len(), 256);
        assert_eq!(v.first().unwrap(), "192.168.1.0");
        assert_eq!(v.last().unwrap(), "192.168.1.255");
    }

    #[test]
    fn cidr_normalises_non_network_base() {
        // /24 given from a host address still yields the whole block.
        let v = parse_spec("192.168.1.37/24", MAX).unwrap();
        assert_eq!(v.len(), 256);
        assert_eq!(v.first().unwrap(), "192.168.1.0");
    }

    #[test]
    fn cidr_32_is_single_host() {
        assert_eq!(parse_spec("10.0.0.1/32", MAX).unwrap(), vec!["10.0.0.1"]);
    }

    #[test]
    fn last_octet_range() {
        let v = parse_spec("192.168.1.0-254", MAX).unwrap();
        assert_eq!(v.len(), 255);
        assert_eq!(v.first().unwrap(), "192.168.1.0");
        assert_eq!(v.last().unwrap(), "192.168.1.254");
    }

    #[test]
    fn full_ip_range() {
        let v = parse_spec("192.168.1.10-192.168.1.20", MAX).unwrap();
        assert_eq!(v.len(), 11);
        assert_eq!(v.first().unwrap(), "192.168.1.10");
        assert_eq!(v.last().unwrap(), "192.168.1.20");
    }

    #[test]
    fn reversed_range_is_rejected() {
        assert_eq!(
            parse_spec("192.168.1.20-192.168.1.10", MAX),
            Err(TargetError::RangeReversed("192.168.1.20-192.168.1.10".into()))
        );
    }

    #[test]
    fn oversized_block_is_capped() {
        // /8 is 16M addresses, well over the default cap.
        assert!(matches!(
            parse_spec("10.0.0.0/8", MAX),
            Err(TargetError::TooLarge { .. })
        ));
    }

    #[test]
    fn bad_cidr_prefix() {
        assert!(matches!(
            parse_spec("192.168.1.0/33", MAX),
            Err(TargetError::BadCidr(_))
        ));
    }

    #[test]
    fn scope_merges_and_dedupes_preserving_order() {
        let inline = vec!["10.0.0.1, DC01.ESSOS.LOCAL".to_string()];
        let file = vec![
            "# a comment".to_string(),
            "".to_string(),
            "10.0.0.1".to_string(), // duplicate of inline
            "10.0.0.2".to_string(),
        ];
        let (hosts, errors) = build_scope(&inline, &file, MAX);
        assert!(errors.is_empty());
        assert_eq!(hosts, vec!["10.0.0.1", "DC01.ESSOS.LOCAL", "10.0.0.2"]);
    }

    #[test]
    fn scope_collects_errors_without_aborting() {
        let inline = vec!["192.168.1.0/33, 10.0.0.5".to_string()];
        let (hosts, errors) = build_scope(&inline, &[], MAX);
        assert_eq!(hosts, vec!["10.0.0.5"]);
        assert_eq!(errors.len(), 1);
    }
}
