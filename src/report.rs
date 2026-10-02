//! Report shapes and rendering.
//!
//! `IsWebClientRunning`, `Collected` and `FailureReason` keep the exact casing
//! RustHound-CE's `Computer` object uses, so the eventual port maps straight onto
//! `objects::computer` without renaming. `running` is the operator-facing view:
//! the subset of hosts that are coercion/ESC8 candidates, the analogue of
//! LocalGroups-rs' `by_principal`.

use colored::Colorize;
use comfy_table::{
    modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Attribute, Cell, Color, ContentArrangement,
    Table,
};
use serde::Serialize;

use crate::scanner::types::{Outcome, PIPE_NAME_DISPLAY};

#[derive(Debug, Clone, Serialize)]
pub struct HostResult {
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(rename = "IsWebClientRunning")]
    pub is_webclient_running: bool,
    #[serde(rename = "Collected")]
    pub collected: bool,
    #[serde(rename = "FailureReason")]
    pub failure_reason: Option<String>,
    pub status: String,
    /// Did the host answer the SMB probe at all. Drives the default (alive-only)
    /// table/status view; kept out of the JSON, which always carries every host.
    #[serde(skip)]
    pub alive: bool,
}

impl HostResult {
    pub fn from_outcome(host: String, address: Option<String>, outcome: &Outcome) -> Self {
        HostResult {
            host,
            address,
            is_webclient_running: outcome.is_running(),
            collected: outcome.collected(),
            failure_reason: outcome.failure_reason(),
            status: outcome.status().to_string(),
            alive: outcome.responded(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub domain: String,
    pub pipe: &'static str,
    pub hosts_scanned: Vec<String>,
    pub running_count: usize,
    pub running: Vec<String>,
    pub computers: Vec<HostResult>,
}

impl Report {
    pub fn build(domain: String, computers: Vec<HostResult>) -> Self {
        let hosts_scanned = computers.iter().map(|c| c.host.clone()).collect();
        let running: Vec<String> = computers
            .iter()
            .filter(|c| c.is_webclient_running)
            .map(|c| c.host.clone())
            .collect();
        Report {
            domain,
            pipe: PIPE_NAME_DISPLAY,
            running_count: running.len(),
            running,
            hosts_scanned,
            computers,
        }
    }

    pub fn to_json(&self, compact: bool) -> String {
        if compact {
            serde_json::to_string(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
        } else {
            serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
        }
    }

    /// Number of hosts that answered the SMB probe (alive).
    pub fn alive_count(&self) -> usize {
        self.computers.iter().filter(|c| c.alive).count()
    }

    /// One terse, tab-separated line per target: `host<TAB>verdict`, where
    /// verdict is `running` / `stopped` / `unknown`. Pipe-friendly for feeding
    /// coercion tooling or diffing scans; no colour, no banner. By default only
    /// hosts that responded are listed; pass `all = true` to include every
    /// target (the unreachable ones show as `unknown`).
    pub fn status_lines(&self, all: bool) -> Vec<String> {
        self.computers
            .iter()
            .filter(|c| all || c.alive)
            .map(|c| {
                let verdict = if c.is_webclient_running {
                    "running"
                } else if c.collected {
                    "stopped"
                } else {
                    "unknown"
                };
                format!("{}\t{verdict}", c.host)
            })
            .collect()
    }

    /// Colored operator table on stdout. By default only hosts that answered the
    /// SMB probe are shown (a wide sweep is mostly timeouts); pass `all = true`
    /// to list every target.
    pub fn render_table(&self, all: bool) -> String {
        let scanned = self.hosts_scanned.len();
        let alive = self.alive_count();

        // Nothing answered: a table of one "no hosts" note reads better than an
        // empty grid, and points at --all for the full picture.
        if !all && alive == 0 {
            return format!(
                "No live hosts responded ({} scanned, all unreachable). \
                 Re-run with --all to list every target.",
                scanned
            );
        }

        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                Cell::new("Host").add_attribute(Attribute::Bold),
                Cell::new("Address").add_attribute(Attribute::Bold),
                Cell::new("WebClient").add_attribute(Attribute::Bold),
                Cell::new("Collected").add_attribute(Attribute::Bold),
                Cell::new("Status").add_attribute(Attribute::Bold),
            ]);

        for c in self.computers.iter().filter(|c| all || c.alive) {
            let (wc_text, wc_color) = if c.is_webclient_running {
                ("RUNNING", Color::Green)
            } else if c.collected {
                ("stopped", Color::DarkGrey)
            } else {
                ("?", Color::Yellow)
            };
            let collected_cell = if c.collected {
                Cell::new("yes").fg(Color::Green)
            } else {
                Cell::new("no").fg(Color::Red)
            };
            table.add_row(vec![
                Cell::new(&c.host),
                Cell::new(c.address.as_deref().unwrap_or("-")),
                Cell::new(wc_text).fg(wc_color).add_attribute(Attribute::Bold),
                collected_cell,
                Cell::new(&c.status),
            ]);
        }

        let hidden = if !all && scanned > alive {
            format!("  ({} unreachable hidden, --all to show)", scanned - alive)
                .dimmed()
                .to_string()
        } else {
            String::new()
        };
        let summary = format!(
            "\n{scanned} scanned  {} alive  {} running WebClient{hidden}",
            alive.to_string().bold(),
            self.running_count.to_string().green().bold()
        );
        format!("{table}{summary}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Report {
        let hosts = vec![
            HostResult::from_outcome("10.0.0.23".into(), None, &Outcome::Running),
            HostResult::from_outcome("10.0.0.12".into(), None, &Outcome::NotRunning),
            HostResult::from_outcome(
                "10.0.0.1".into(),
                None,
                &Outcome::Unreachable("timed out".into()),
            ),
        ];
        Report::build("LAB.LOCAL".into(), hosts)
    }

    #[test]
    fn alive_count_excludes_unreachable() {
        assert_eq!(sample().alive_count(), 2);
    }

    #[test]
    fn status_lines_default_hides_dead() {
        let r = sample();
        assert_eq!(r.status_lines(false).len(), 2);
        assert_eq!(r.status_lines(true).len(), 3);
    }

    #[test]
    fn table_default_hides_dead_but_all_shows_it() {
        let r = sample();
        let def = r.render_table(false);
        assert!(def.contains("10.0.0.23") && def.contains("10.0.0.12"));
        assert!(!def.contains("10.0.0.1\n") && !def.contains("10.0.0.1 "));
        let all = r.render_table(true);
        assert!(all.contains("10.0.0.1"));
    }

    #[test]
    fn json_always_carries_every_host() {
        // The report keeps all hosts regardless of the alive view.
        assert_eq!(sample().computers.len(), 3);
    }
}