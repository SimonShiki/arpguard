use crate::forensics::ForensicReport;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::Command;

pub struct IncidentNotifier {
    /// Rate-limit map: `(attack_kind, attacker_mac, target_ip)` -> last notification unix timestamp
    last_notified: HashMap<(String, String, String), u64>,
    cooldown_secs: u64,
}

impl IncidentNotifier {
    pub fn new(cooldown_secs: u64) -> Self {
        Self {
            last_notified: HashMap::new(),
            cooldown_secs,
        }
    }

    /// Logs the forensic report to stderr, appends a JSONL record to `log_path`,
    /// and dispatches a desktop notification (rate-limited by `cooldown_secs`).
    pub fn handle_incident(
        &mut self,
        report: &ForensicReport,
        log_path: Option<&Path>,
        enable_desktop_notify: bool,
    ) {
        let key = (
            report.attack_kind.clone(),
            report.attacker_mac.clone(),
            report.target_ip.clone(),
        );
        if let Some(&prev_ts) = self.last_notified.get(&key) {
            if report.timestamp_unix.saturating_sub(prev_ts) < self.cooldown_secs {
                return;
            }
        }
        self.last_notified.insert(key, report.timestamp_unix);

        let ips_display = if report.attacker_ips.is_empty() {
            "unknown (spoofing only)".to_string()
        } else {
            report.attacker_ips.join(", ")
        };
        let hosts_display = if report.attacker_hostnames.is_empty() {
            "unknown".to_string()
        } else {
            report.attacker_hostnames.join(", ")
        };

        eprintln!(
            "[ALERT] {} on {} (SSID: {})\n  Target IP      : {} (Real MAC: {})\n  Attacker MAC   : {} ({})\n  Attacker IP(s) : {}\n  Hostname(s)    : {}\n  Mitigation     : {}",
            report.attack_title,
            report.iface,
            report.ssid.as_deref().unwrap_or("N/A"),
            report.target_ip,
            report.legitimate_mac.as_deref().unwrap_or("N/A"),
            report.attacker_mac,
            report.attacker_vendor,
            ips_display,
            hosts_display,
            report.mitigation_action
        );

        if let Some(path) = log_path {
            if let Err(e) = append_jsonl_report(path, report) {
                eprintln!("[WARN] Failed to write incident log {}: {}", path.display(), e);
            }
        }

        if enable_desktop_notify {
            send_desktop_notification(report, &ips_display, &hosts_display);
        }
    }
}

pub fn format_jsonl(report: &ForensicReport) -> String {
    let ssid_json = match &report.ssid {
        Some(s) => format!("\"{}\"", escape_json(s)),
        None => "null".to_string(),
    };
    let legit_mac_json = match &report.legitimate_mac {
        Some(m) => format!("\"{}\"", escape_json(m)),
        None => "null".to_string(),
    };
    let ips_json: Vec<String> = report
        .attacker_ips
        .iter()
        .map(|s| format!("\"{}\"", escape_json(s)))
        .collect();
    let hosts_json: Vec<String> = report
        .attacker_hostnames
        .iter()
        .map(|s| format!("\"{}\"", escape_json(s)))
        .collect();

    format!(
        "{{\"timestamp\":{},\"iface\":\"{}\",\"ssid\":{},\"attack_kind\":\"{}\",\"target_ip\":\"{}\",\"legitimate_mac\":{},\"attacker_mac\":\"{}\",\"attacker_vendor\":\"{}\",\"attacker_ips\":[{}],\"attacker_hostnames\":[{}],\"mitigation\":\"{}\"}}",
        report.timestamp_unix,
        escape_json(&report.iface),
        ssid_json,
        escape_json(&report.attack_kind),
        escape_json(&report.target_ip),
        legit_mac_json,
        escape_json(&report.attacker_mac),
        escape_json(&report.attacker_vendor),
        ips_json.join(","),
        hosts_json.join(","),
        escape_json(&report.mitigation_action)
    )
}

pub fn append_jsonl_report(path: &Path, report: &ForensicReport) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    let mut line = format_jsonl(report);
    line.push('\n');
    file.write_all(line.as_bytes()).map_err(|e| e.to_string())
}

fn send_desktop_notification(report: &ForensicReport, ips_display: &str, hosts_display: &str) {
    let summary = format!("ARPGuard: {}", report.attack_title);
    let body = format!(
        "Target: {} ({})\nAttacker MAC: {} ({})\nAttacker IP: {}\nHostname: {}\nAction: {}",
        report.target_ip,
        report.iface,
        report.attacker_mac,
        report.attacker_vendor,
        ips_display,
        hosts_display,
        report.mitigation_action
    );

    // If running inside a desktop user session already (DBUS_SESSION_BUS_ADDRESS is set), invoke notify-send directly
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some() {
        let _ = Command::new("/usr/bin/notify-send")
            .args([
                "-u",
                "critical",
                "-a",
                "ARPGuard",
                "-i",
                "security-high",
                &summary,
                &body,
            ])
            .status();
        return;
    }

    // When running as root under systemd, discover active desktop user's /run/user/<uid>/bus
    if let Ok(entries) = fs::read_dir("/run/user") {
        for entry in entries.flatten() {
            let uid_str = entry.file_name().to_string_lossy().to_string();
            if uid_str == "0" || !uid_str.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let bus_path = entry.path().join("bus");
            if bus_path.exists() {
                if let Some(username) = lookup_username_by_uid(&uid_str) {
                    let bus_addr = format!("unix:path={}", bus_path.display());
                    let _ = Command::new("/usr/bin/runuser")
                        .args([
                            "-u",
                            &username,
                            "--",
                            "/usr/bin/env",
                            &format!("DBUS_SESSION_BUS_ADDRESS={}", bus_addr),
                            "/usr/bin/notify-send",
                            "-u",
                            "critical",
                            "-a",
                            "ARPGuard",
                            "-i",
                            "security-high",
                            &summary,
                            &body,
                        ])
                        .status();
                }
            }
        }
    }
}

fn lookup_username_by_uid(uid: &str) -> Option<String> {
    let content = fs::read_to_string("/etc/passwd").ok()?;
    for line in content.lines() {
        let cols: Vec<&str> = line.split(':').collect();
        if cols.len() >= 3 && cols[2] == uid {
            return Some(cols[0].to_string());
        }
    }
    None
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_jsonl() {
        let rep = ForensicReport {
            timestamp_unix: 1700000000,
            iface: "wlan0".to_string(),
            ssid: Some("School_WiFi".to_string()),
            attack_kind: "gateway_spoof_by_known_peer".to_string(),
            attack_title: "CRITICAL: Gateway ARP Spoofing".to_string(),
            target_ip: "192.168.1.1".to_string(),
            legitimate_mac: Some("aa:bb:cc:11:22:33".to_string()),
            attacker_mac: "de:ad:be:ef:00:01".to_string(),
            attacker_vendor: "Intel Corporate".to_string(),
            attacker_ips: vec!["192.168.1.50".to_string()],
            attacker_hostnames: vec!["evil-laptop.local (mDNS)".to_string()],
            mitigation_action: "Locked gateway 192.168.1.1 -> aa:bb:cc:11:22:33".to_string(),
        };
        let json = format_jsonl(&rep);
        assert!(json.contains("\"attack_kind\":\"gateway_spoof_by_known_peer\""));
        assert!(json.contains("\"attacker_ips\":[\"192.168.1.50\"]"));
        assert!(json.contains("\"attacker_hostnames\":[\"evil-laptop.local (mDNS)\"]"));
    }
}
