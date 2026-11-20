use crate::oui::{normalize_mac, DEFAULT_ETHERCODES_PATH};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Sender;
use std::thread;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArpEventKind {
    NewStation,
    NewActivity,
    ChangedEthernetAddress,
    FlipFlop,
    ReusedOldEthernetAddress,
    EthernetMismatch,
    Bogon,
    EthernetBroadcast,
    IpBroadcast,
    Other(String),
}

impl ArpEventKind {
    pub fn from_subject(subject: &str) -> Self {
        let s = subject.trim().to_ascii_lowercase();
        let base = s.split('(').next().unwrap_or(&s).trim();
        match base {
            "new station" => Self::NewStation,
            "new activity" => Self::NewActivity,
            "changed ethernet address" => Self::ChangedEthernetAddress,
            "flip flop" => Self::FlipFlop,
            "reused old ethernet address" => Self::ReusedOldEthernetAddress,
            "ethernet mismatch" => Self::EthernetMismatch,
            "bogon" => Self::Bogon,
            "ethernet broadcast" => Self::EthernetBroadcast,
            "ip broadcast" => Self::IpBroadcast,
            other => Self::Other(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::NewStation => "new_station",
            Self::NewActivity => "new_activity",
            Self::ChangedEthernetAddress => "changed_ethernet_address",
            Self::FlipFlop => "flip_flop",
            Self::ReusedOldEthernetAddress => "reused_old_ethernet_address",
            Self::EthernetMismatch => "ethernet_mismatch",
            Self::Bogon => "bogon",
            Self::EthernetBroadcast => "ethernet_broadcast",
            Self::IpBroadcast => "ip_broadcast",
            Self::Other(s) => s.as_str(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpEvent {
    pub kind: ArpEventKind,
    pub ip: String,
    pub mac: String,
    pub old_mac: Option<String>,
    pub vendor: Option<String>,
    pub old_vendor: Option<String>,
    pub hostname: Option<String>,
    pub delta_seconds: Option<u64>,
    pub raw_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpDatRecord {
    pub mac: String,
    pub ip: String,
    pub timestamp: u64,
    pub hostname: Option<String>,
}

/// Stateful line-by-line parser for `arpwatch -d` stdout report blocks.
#[derive(Default)]
pub struct ArpwatchStdoutParser {
    in_block: bool,
    subject: Option<String>,
    hostname: Option<String>,
    ip: Option<String>,
    mac: Option<String>,
    old_mac: Option<String>,
    vendor: Option<String>,
    old_vendor: Option<String>,
    delta_seconds: Option<u64>,
}

impl ArpwatchStdoutParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed_line(&mut self, line: &str) -> Option<ArpEvent> {
        let trimmed = line.trim();

        if trimmed.starts_with("From:") {
            let prev = self.take_completed_event();
            self.in_block = true;
            return prev;
        }

        if !self.in_block {
            return None;
        }

        if let Some(rest) = trimmed.strip_prefix("Subject:") {
            self.subject = Some(rest.trim().to_string());
            return None;
        }

        if let Some((key, val)) = trimmed.split_once(':') {
            let key = key.trim().to_ascii_lowercase();
            let val = val.trim();
            match key.as_str() {
                "hostname" => {
                    if val != "<unknown>" && !val.is_empty() {
                        self.hostname = Some(val.to_string());
                    }
                }
                "ip address" => {
                    self.ip = Some(val.to_string());
                }
                "ethernet address" => {
                    self.mac = Some(normalize_mac(val));
                }
                "ethernet vendor" => {
                    if val != "<unknown>" && !val.is_empty() {
                        self.vendor = Some(val.to_string());
                    }
                }
                "old ethernet address" => {
                    self.old_mac = Some(normalize_mac(val));
                }
                "old ethernet vendor" => {
                    if val != "<unknown>" && !val.is_empty() {
                        self.old_vendor = Some(val.to_string());
                    }
                }
                "delta" => {
                    self.delta_seconds = parse_delta_seconds(val);
                    // `delta:` is always the final line in change/flip-flop blocks
                    return self.take_completed_event();
                }
                "timestamp" => {
                    // For `new station` / `new activity`, `timestamp:` is the last line
                    if let Some(subj) = &self.subject {
                        let kind = ArpEventKind::from_subject(subj);
                        if matches!(kind, ArpEventKind::NewStation | ArpEventKind::NewActivity) {
                            return self.take_completed_event();
                        }
                    }
                }
                _ => {}
            }
        }

        None
    }

    pub fn flush(&mut self) -> Option<ArpEvent> {
        self.take_completed_event()
    }

    fn take_completed_event(&mut self) -> Option<ArpEvent> {
        let subject = self.subject.take()?;
        let ip = self.ip.take()?;
        let mac = self.mac.take()?;
        let kind = ArpEventKind::from_subject(&subject);
        let old_mac = self.old_mac.take();
        let vendor = self.vendor.take();
        let old_vendor = self.old_vendor.take();
        let hostname = self.hostname.take();
        let delta_seconds = self.delta_seconds.take();
        self.in_block = false;

        let raw_summary = match &old_mac {
            Some(old) => format!("{} {} {} (was {})", kind.as_str(), ip, mac, old),
            None => format!("{} {} {}", kind.as_str(), ip, mac),
        };

        Some(ArpEvent {
            kind,
            ip,
            mac,
            old_mac,
            vendor,
            old_vendor,
            hostname,
            delta_seconds,
            raw_summary,
        })
    }
}

/// Parses single-line warning outputs from `arpwatch` stderr, e.g.:
/// `arpwatch: ethernet mismatch 192.168.1.1 de:ad:be:ef:00:01 (11:22:33:44:55:66)`
/// `arpwatch: reused old ethernet address 192.168.1.1 de:ad:be:ef:00:01 (aa:bb:cc:11:22:33)`
pub fn parse_arpwatch_stderr_line(line: &str) -> Option<ArpEvent> {
    let trimmed = line.trim();
    let msg = trimmed.strip_prefix("arpwatch:").unwrap_or(trimmed).trim();
    if msg.starts_with("Warning:") || msg.is_empty() {
        return None;
    }

    let prefixes = [
        ("ethernet mismatch ", ArpEventKind::EthernetMismatch),
        (
            "reused old ethernet address ",
            ArpEventKind::ReusedOldEthernetAddress,
        ),
        ("flip flop ", ArpEventKind::FlipFlop),
        (
            "changed ethernet address ",
            ArpEventKind::ChangedEthernetAddress,
        ),
        ("new station ", ArpEventKind::NewStation),
        ("new activity ", ArpEventKind::NewActivity),
        ("bogon ", ArpEventKind::Bogon),
        ("ethernet broadcast ", ArpEventKind::EthernetBroadcast),
        ("ip broadcast ", ArpEventKind::IpBroadcast),
    ];

    for (prefix, kind) in prefixes {
        if let Some(rest) = msg.strip_prefix(prefix) {
            // Expected tokens: <ip> <mac> [(<old_or_inner_mac>)]
            let tokens: Vec<&str> = rest.split_whitespace().collect();
            if tokens.len() >= 2 {
                let ip = tokens[0].to_string();
                let mac = normalize_mac(tokens[1]);
                let old_mac = tokens.get(2).map(|t| {
                    let clean = t.trim_matches(|c| c == '(' || c == ')');
                    normalize_mac(clean)
                });
                return Some(ArpEvent {
                    kind,
                    ip,
                    mac,
                    old_mac,
                    vendor: None,
                    old_vendor: None,
                    hostname: None,
                    delta_seconds: None,
                    raw_summary: msg.to_string(),
                });
            }
        }
    }
    None
}

fn parse_delta_seconds(val: &str) -> Option<u64> {
    let mut parts = val.split_whitespace();
    let num: u64 = parts.next()?.parse().ok()?;
    let unit = parts.next().unwrap_or("seconds").to_ascii_lowercase();
    if unit.starts_with("min") {
        Some(num * 60)
    } else if unit.starts_with("hour") {
        Some(num * 3600)
    } else if unit.starts_with("day") {
        Some(num * 86400)
    } else {
        Some(num)
    }
}

/// Parses `arp.dat` written by `arpwatch`.
pub fn read_arp_dat(path: &Path) -> Vec<ArpDatRecord> {
    let mut out = Vec::new();
    let Ok(file) = File::open(path) else {
        return out;
    };
    let reader = BufReader::new(file);
    for line in reader.lines().map_while(Result::ok) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() >= 3 {
            let mac = normalize_mac(cols[0]);
            let ip = cols[1].trim().to_string();
            let timestamp = cols[2].trim().parse::<u64>().unwrap_or(0);
            let hostname = cols
                .get(3)
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty());
            out.push(ArpDatRecord {
                mac,
                ip,
                timestamp,
                hostname,
            });
        }
    }
    out
}

pub struct ArpwatchProcess {
    pub child: Child,
    pub dat_path: PathBuf,
}

impl ArpwatchProcess {
    /// Prepares `<workdir>`, symlinks `ethercodes.dat`, initializes `<dat_file>`,
    /// and spawns `arpwatch -d -p -N -z -Z -v` streaming events to `tx`.
    pub fn spawn_live(
        iface: &str,
        network_id: &str,
        workdir: &Path,
        tx: Sender<ArpEvent>,
    ) -> Result<Self, String> {
        fs::create_dir_all(workdir)
            .map_err(|e| format!("Failed to create workdir {}: {}", workdir.display(), e))?;

        let ethercodes_dst = workdir.join("ethercodes.dat");
        if !ethercodes_dst.exists() && Path::new(DEFAULT_ETHERCODES_PATH).exists() {
            let _ = symlink(DEFAULT_ETHERCODES_PATH, &ethercodes_dst);
        }

        let safe_net_id: String = network_id
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        let dat_path = workdir.join(format!("arp-{}-{}.dat", iface, safe_net_id));
        if !dat_path.exists() {
            File::create(&dat_path)
                .map_err(|e| format!("Failed to create {}: {}", dat_path.display(), e))?;
        }

        let mut child = Command::new("/usr/bin/arpwatch")
            .args([
                "-d",
                "-p",
                "-N",
                "-z",
                "-Z",
                "-v",
                "-D",
                workdir.to_str().unwrap_or("/run/arpguard"),
                "-f",
                dat_path.to_str().unwrap_or("arp.dat"),
                "-i",
                iface,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn /usr/bin/arpwatch: {}", e))?;

        Self::attach_reader_threads(&mut child, tx);

        Ok(Self { child, dat_path })
    }

    /// Runs `arpwatch -r <pcap>` offline on a packet capture file and returns all parsed events
    /// and the resulting `arp.dat` entries.
    pub fn run_pcap_replay(
        pcap_path: &Path,
        workdir: &Path,
    ) -> Result<(Vec<ArpEvent>, Vec<ArpDatRecord>), String> {
        fs::create_dir_all(workdir)
            .map_err(|e| format!("Failed to create workdir {}: {}", workdir.display(), e))?;
        let ethercodes_dst = workdir.join("ethercodes.dat");
        if !ethercodes_dst.exists() && Path::new(DEFAULT_ETHERCODES_PATH).exists() {
            let _ = symlink(DEFAULT_ETHERCODES_PATH, &ethercodes_dst);
        }
        let dat_path = workdir.join("replay-arp.dat");
        File::create(&dat_path)
            .map_err(|e| format!("Failed to create {}: {}", dat_path.display(), e))?;

        let output = Command::new("/usr/bin/arpwatch")
            .args([
                "-d",
                "-N",
                "-z",
                "-Z",
                "-v",
                "-D",
                workdir.to_str().unwrap_or("/tmp"),
                "-f",
                dat_path.to_str().unwrap_or("replay-arp.dat"),
                "-r",
                pcap_path.to_str().unwrap_or(""),
            ])
            .output()
            .map_err(|e| format!("Failed to execute arpwatch replay: {}", e))?;

        let mut events = Vec::new();
        let mut parser = ArpwatchStdoutParser::new();
        let stdout_str = String::from_utf8_lossy(&output.stdout);
        for line in stdout_str.lines() {
            if let Some(ev) = parser.feed_line(line) {
                events.push(ev);
            }
        }
        if let Some(ev) = parser.flush() {
            events.push(ev);
        }

        let stderr_str = String::from_utf8_lossy(&output.stderr);
        for line in stderr_str.lines() {
            if let Some(ev) = parse_arpwatch_stderr_line(line) {
                events.push(ev);
            }
        }

        let records = read_arp_dat(&dat_path);
        Ok((events, records))
    }

    fn attach_reader_threads(child: &mut Child, tx: Sender<ArpEvent>) {
        if let Some(stdout) = child.stdout.take() {
            let tx_out = tx.clone();
            thread::spawn(move || {
                let reader = BufReader::new(stdout);
                let mut parser = ArpwatchStdoutParser::new();
                for line in reader.lines().map_while(Result::ok) {
                    if let Some(ev) = parser.feed_line(&line) {
                        let _ = tx_out.send(ev);
                    }
                }
                if let Some(ev) = parser.flush() {
                    let _ = tx_out.send(ev);
                }
            });
        }

        if let Some(stderr) = child.stderr.take() {
            thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines().map_while(Result::ok) {
                    if let Some(ev) = parse_arpwatch_stderr_line(&line) {
                        let _ = tx.send(ev);
                    }
                }
            });
        }
    }

    /// Sends SIGHUP to `arpwatch` so it immediately dumps its in-memory table to `dat_path`.
    pub fn flush_and_read_dat(&self) -> Vec<ArpDatRecord> {
        let pid = self.child.id();
        let _ = Command::new("/usr/bin/kill")
            .args(["-HUP", &pid.to_string()])
            .status();
        std::thread::sleep(std::time::Duration::from_millis(25));
        read_arp_dat(&self.dat_path)
    }

    pub fn terminate(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for ArpwatchProcess {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stdout_parser_blocks() {
        let sample = "\
From: arpwatch
To: arpwatch
Subject: new station

            hostname: <unknown>
          ip address: 192.168.1.1
    ethernet address: aa:bb:cc:11:22:33
     ethernet vendor: Cisco Systems, Inc
           timestamp: Thursday, January 1, 1970 8:16:40 +0800

From: arpwatch
To: arpwatch
Subject: changed ethernet address

            hostname: attacker-pc
          ip address: 192.168.1.1
    ethernet address: de:ad:be:ef:00:01
     ethernet vendor: <unknown>
old ethernet address: aa:bb:cc:11:22:33
 old ethernet vendor: Cisco Systems, Inc
           timestamp: Thursday, January 1, 1970 8:16:45 +0800
  previous timestamp: Thursday, January 1, 1970 8:16:40 +0800
               delta: 5 seconds
";
        let mut parser = ArpwatchStdoutParser::new();
        let mut events = Vec::new();
        for line in sample.lines() {
            if let Some(ev) = parser.feed_line(line) {
                events.push(ev);
            }
        }
        if let Some(ev) = parser.flush() {
            events.push(ev);
        }
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, ArpEventKind::NewStation);
        assert_eq!(events[0].ip, "192.168.1.1");
        assert_eq!(events[0].mac, "aa:bb:cc:11:22:33");
        assert_eq!(events[0].vendor.as_deref(), Some("Cisco Systems, Inc"));

        assert_eq!(events[1].kind, ArpEventKind::ChangedEthernetAddress);
        assert_eq!(events[1].ip, "192.168.1.1");
        assert_eq!(events[1].mac, "de:ad:be:ef:00:01");
        assert_eq!(events[1].old_mac.as_deref(), Some("aa:bb:cc:11:22:33"));
        assert_eq!(events[1].hostname.as_deref(), Some("attacker-pc"));
        assert_eq!(events[1].delta_seconds, Some(5));
    }

    #[test]
    fn test_stderr_parser() {
        let line = "arpwatch: ethernet mismatch 192.168.1.1 de:ad:be:ef:00:01 (11:22:33:44:55:66)";
        let ev = parse_arpwatch_stderr_line(line).expect("should parse stderr mismatch");
        assert_eq!(ev.kind, ArpEventKind::EthernetMismatch);
        assert_eq!(ev.ip, "192.168.1.1");
        assert_eq!(ev.mac, "de:ad:be:ef:00:01");
        assert_eq!(ev.old_mac.as_deref(), Some("11:22:33:44:55:66"));
    }
}
