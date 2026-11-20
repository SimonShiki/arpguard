use crate::oui::normalize_mac;
use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Sender;
use std::thread;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkContext {
    pub iface: String,
    pub gateway_ip: Option<String>,
    pub verified_gateway_mac: Option<String>,
    pub local_ip: Option<String>,
    pub local_mac: Option<String>,
    pub ssid: Option<String>,
    pub network_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetlinkEvent {
    RouteOrAddrChanged(String),
    NeighChanged {
        ip: String,
        dev: String,
        mac: Option<String>,
        state: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpingProbeResult {
    pub replying_macs: Vec<String>,
}

/// Discovers the current active network context for `iface_override` (or the default route's interface).
/// When `iface_override` is provided, only default routes bound to that specific interface are used.
pub fn discover_network_context(iface_override: Option<&str>) -> Option<NetworkContext> {
    let route_out = Command::new("/usr/bin/ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .ok()?;
    let route_text = String::from_utf8_lossy(&route_out.stdout);
    let (iface_opt, gateway_ip) = parse_default_route_for_iface(&route_text, iface_override);
    let iface = iface_opt?;

    // Verify interface exists in sysfs when explicitly specified
    let sysfs_addr = format!("/sys/class/net/{}/address", iface);
    let local_mac = fs::read_to_string(&sysfs_addr)
        .ok()
        .map(|s| normalize_mac(s.trim()))
        .filter(|s| !s.is_empty());

    let local_ip = query_interface_ipv4(&iface);
    let ssid = query_wifi_ssid(&iface);

    let verified_gateway_mac = gateway_ip
        .as_deref()
        .and_then(|gw| query_kernel_neigh_mac(&iface, gw));

    let network_id = format!(
        "{}_{}_{}",
        iface,
        ssid.as_deref().unwrap_or("lan"),
        gateway_ip.as_deref().unwrap_or("nogw")
    );

    Some(NetworkContext {
        iface,
        gateway_ip,
        verified_gateway_mac,
        local_ip,
        local_mac,
        ssid,
        network_id,
    })
}

/// Parses `ip -4 route show default` output.
/// If `iface_filter` is `Some(target_dev)`, only matches default routes on `target_dev` and never
/// pairs `target_dev` with another interface's gateway.
pub fn parse_default_route_for_iface(
    route_output: &str,
    iface_filter: Option<&str>,
) -> (Option<String>, Option<String>) {
    for line in route_output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.first() == Some(&"default") {
            let mut gw = None;
            let mut dev = None;
            let mut i = 1;
            while i < tokens.len() {
                match tokens[i] {
                    "via" if i + 1 < tokens.len() => {
                        gw = Some(tokens[i + 1].to_string());
                        i += 2;
                    }
                    "dev" if i + 1 < tokens.len() => {
                        dev = Some(tokens[i + 1].to_string());
                        i += 2;
                    }
                    _ => i += 1,
                }
            }
            if let Some(ref d) = dev {
                match iface_filter {
                    Some(target) if d == target => return (Some(target.to_string()), gw),
                    Some(_) => continue,
                    None => return (dev, gw),
                }
            }
        }
    }
    match iface_filter {
        Some(target) => (Some(target.to_string()), None),
        None => (None, None),
    }
}

pub fn parse_default_route(route_output: &str) -> (Option<String>, Option<String>) {
    parse_default_route_for_iface(route_output, None)
}

pub fn query_interface_ipv4(iface: &str) -> Option<String> {
    let out = Command::new("/usr/bin/ip")
        .args(["-4", "-o", "addr", "show", "dev", iface])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        for (idx, tok) in tokens.iter().enumerate() {
            if *tok == "inet" {
                if let Some(cidr) = tokens.get(idx + 1) {
                    return Some(cidr.split('/').next().unwrap_or(cidr).to_string());
                }
            }
        }
    }
    None
}

/// Queries the actual 802.11 Wi-Fi SSID (and BSSID when available) rather than relying solely
/// on NetworkManager's connection profile name:
/// 1. First queries kernel nl80211 directly via `/usr/bin/iw dev <iface> link`.
/// 2. Falls back to `nmcli -t -f active,ssid,bssid dev wifi list ifname <iface>`.
/// 3. Falls back to `nmcli -g GENERAL.CONNECTION device show <iface>` for non-Wi-Fi interfaces.
pub fn query_wifi_ssid(iface: &str) -> Option<String> {
    if let Ok(out) = Command::new("/usr/bin/iw")
        .args(["dev", iface, "link"])
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            if let Some(ssid) = parse_iw_link_ssid(&text) {
                return Some(ssid);
            }
        }
    }

    if let Ok(out) = Command::new("/usr/bin/nmcli")
        .args(["-t", "-f", "active,ssid", "dev", "wifi", "list", "ifname", iface])
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                if let Some(ssid) = line.strip_prefix("yes:") {
                    let s = ssid.trim();
                    if !s.is_empty() && s != "--" {
                        return Some(s.to_string());
                    }
                }
            }
        }
    }

    let out = Command::new("/usr/bin/nmcli")
        .args(["-g", "GENERAL.CONNECTION", "device", "show", iface])
        .output()
        .ok()?;
    if out.status.success() {
        let conn = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !conn.is_empty() && conn != "--" {
            return Some(conn);
        }
    }
    None
}

pub fn parse_iw_link_ssid(iw_output: &str) -> Option<String> {
    let mut ssid = None;
    for line in iw_output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("SSID:") {
            let s = rest.trim();
            if !s.is_empty() {
                ssid = Some(s.to_string());
            }
        }
    }
    ssid
}

pub fn query_kernel_neigh_mac(iface: &str, ip: &str) -> Option<String> {
    let out = Command::new("/usr/bin/ip")
        .args(["-4", "neigh", "show", ip, "dev", iface])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        for (idx, tok) in tokens.iter().enumerate() {
            if *tok == "lladdr" {
                if let Some(mac) = tokens.get(idx + 1) {
                    return Some(normalize_mac(mac));
                }
            }
        }
    }
    None
}

/// Returns all `(ip, mac)` entries currently in the kernel neighbor table for `iface`.
pub fn list_kernel_neighbors(iface: &str) -> Vec<(String, String)> {
    let mut results = Vec::new();
    let Ok(out) = Command::new("/usr/bin/ip")
        .args(["-4", "neigh", "show", "dev", iface])
        .output()
    else {
        return results;
    };
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        let ip = tokens[0].to_string();
        for (idx, tok) in tokens.iter().enumerate() {
            if *tok == "lladdr" {
                if let Some(mac) = tokens.get(idx + 1) {
                    results.push((ip, normalize_mac(mac)));
                    break;
                }
            }
        }
    }
    results
}

/// Sends a fast active ARP probe (`arping -c 2 -w 1 -I <iface> <target_ip>`)
/// and extracts all distinct replying MAC addresses.
/// - If 2+ different MACs reply to the same IP -> active MITM race on the LAN.
/// - Used during gateway conflict disambiguation to test if the old gateway MAC is still alive.
pub fn probe_arp_replies(iface: &str, target_ip: &str) -> ArpingProbeResult {
    let Ok(out) = Command::new("/usr/bin/arping")
        .args(["-c", "2", "-w", "1", "-I", iface, target_ip])
        .output()
    else {
        return ArpingProbeResult {
            replying_macs: Vec::new(),
        };
    };
    let text = String::from_utf8_lossy(&out.stdout);
    parse_arping_output(&text)
}

pub fn parse_arping_output(output: &str) -> ArpingProbeResult {
    let mut seen = HashSet::new();
    let mut macs = Vec::new();
    for line in output.lines() {
        // iputils arping format:
        // "Unicast reply from 192.168.1.1 [AA:BB:CC:11:22:33]  1.234ms"
        if let (Some(start), Some(end)) = (line.find('['), line.find(']')) {
            if end > start + 1 {
                let candidate = normalize_mac(&line[start + 1..end]);
                if candidate.split(':').count() == 6 && seen.insert(candidate.clone()) {
                    macs.push(candidate);
                }
            }
        }
    }
    ArpingProbeResult {
        replying_macs: macs,
    }
}

/// Pins the verified gateway MAC in the Linux kernel neighbor table (`nud permanent`),
/// preventing unsolicited/spoofed ARP replies from hijacking the user's traffic.
pub fn pin_gateway_mac(iface: &str, gw_ip: &str, gw_mac: &str, dry_run: bool) -> Result<(), String> {
    let norm_mac = normalize_mac(gw_mac);
    if dry_run {
        return Ok(());
    }
    let status = Command::new("/usr/bin/ip")
        .args([
            "neigh",
            "replace",
            gw_ip,
            "lladdr",
            &norm_mac,
            "nud",
            "permanent",
            "dev",
            iface,
        ])
        .status()
        .map_err(|e| format!("Failed to invoke ip neigh replace: {}", e))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "ip neigh replace {} lladdr {} failed with status {}",
            gw_ip, norm_mac, status
        ))
    }
}

/// Re-asserts our own IP->MAC mapping via Gratuitous ARP (`arping -U -c 1`) when an IP conflict is detected.
pub fn defend_local_ip(iface: &str, local_ip: &str, dry_run: bool) {
    if dry_run {
        return;
    }
    let _ = Command::new("/usr/bin/arping")
        .args(["-U", "-c", "1", "-w", "1", "-I", iface, local_ip])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Optionally blocks incoming ARP packets from a confirmed attacker MAC via `arptables`.
pub fn block_attacker_arp(iface: &str, attacker_mac: &str, gw_ip: &str, dry_run: bool) {
    if dry_run {
        return;
    }
    let norm_mac = normalize_mac(attacker_mac);
    // Avoid duplicating the rule if already present
    let check = Command::new("/usr/bin/arptables")
        .args([
            "-C",
            "INPUT",
            "-i",
            iface,
            "--source-mac",
            &norm_mac,
            "-s",
            gw_ip,
            "-j",
            "DROP",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if check.map(|s| s.success()).unwrap_or(false) {
        return;
    }
    let _ = Command::new("/usr/bin/arptables")
        .args([
            "-A",
            "INPUT",
            "-i",
            iface,
            "--source-mac",
            &norm_mac,
            "-s",
            gw_ip,
            "-j",
            "DROP",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Spawns `ip -4 monitor route neigh addr` as a zero-polling event stream.
pub fn spawn_netlink_monitor(tx: Sender<NetlinkEvent>) -> Result<Child, String> {
    let mut child = Command::new("/usr/bin/ip")
        .args(["-4", "monitor", "route", "neigh", "addr"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to spawn ip monitor: {}", e))?;

    if let Some(stdout) = child.stdout.take() {
        thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                if let Some(ev) = parse_ip_monitor_line(&line) {
                    let _ = tx.send(ev);
                }
            }
        });
    }

    Ok(child)
}

pub fn parse_ip_monitor_line(line: &str) -> Option<NetlinkEvent> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let clean = trimmed.strip_prefix("Deleted ").unwrap_or(trimmed);
    // Route change or IPv4 address assignment/removal (e.g. "2: wlan0    inet 10.0.0.45/24 ...")
    if clean.starts_with("default ")
        || clean.contains(" via ")
        || clean.contains(" inet ")
        || clean.starts_with("inet ")
    {
        return Some(NetlinkEvent::RouteOrAddrChanged(trimmed.to_string()));
    }
    // Neighbor line format:
    // "192.168.1.1 dev wlan0 lladdr aa:bb:cc:11:22:33 REACHABLE"
    let tokens: Vec<&str> = clean.split_whitespace().collect();
    if tokens.len() >= 4 && tokens[1] == "dev" && tokens[0].chars().any(|c| c == '.') {
        let ip = tokens[0].to_string();
        let dev = tokens[2].to_string();
        let mut mac = None;
        for (idx, tok) in tokens.iter().enumerate() {
            if *tok == "lladdr" {
                if let Some(m) = tokens.get(idx + 1) {
                    mac = Some(normalize_mac(m));
                }
            }
        }
        let state = tokens.last().copied().unwrap_or("").to_string();
        return Some(NetlinkEvent::NeighChanged {
            ip,
            dev,
            mac,
            state,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_default_route_and_iface_filter() {
        let multi_route = "\
default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.10 metric 100
default via 10.0.0.1 dev wlan0 proto dhcp src 10.0.0.100 metric 600
";
        let (dev_default, gw_default) = parse_default_route(multi_route);
        assert_eq!(dev_default.as_deref(), Some("eth0"));
        assert_eq!(gw_default.as_deref(), Some("192.168.1.1"));

        // Explicit --iface wlan0 must match wlan0's gateway (10.0.0.1), not eth0's!
        let (dev_wlan, gw_wlan) = parse_default_route_for_iface(multi_route, Some("wlan0"));
        assert_eq!(dev_wlan.as_deref(), Some("wlan0"));
        assert_eq!(gw_wlan.as_deref(), Some("10.0.0.1"));

        // Interface with no default route must not inherit another interface's gateway
        let (dev_wg, gw_wg) = parse_default_route_for_iface(multi_route, Some("wg0"));
        assert_eq!(dev_wg.as_deref(), Some("wg0"));
        assert_eq!(gw_wg, None);
    }

    #[test]
    fn test_parse_iw_link_ssid() {
        let sample = "\
Connected to 00:11:22:33:44:55 (on wlan0)
\tSSID: Campus_Eduroam_5G
\tfreq: 5180
\tRX: 123456 bytes
";
        assert_eq!(
            parse_iw_link_ssid(sample).as_deref(),
            Some("Campus_Eduroam_5G")
        );
        assert_eq!(parse_iw_link_ssid("Not connected.\n"), None);
    }

    #[test]
    fn test_parse_arping_output() {
        let sample = "\
ARPING 192.168.1.1 from 192.168.1.100 wlan0
Unicast reply from 192.168.1.1 [AA:BB:CC:11:22:33]  1.120ms
Unicast reply from 192.168.1.1 [DE:AD:BE:EF:00:01]  1.450ms
Sent 2 probes (1 broadcast(s))
Received 2 response(s)
";
        let res = parse_arping_output(sample);
        assert_eq!(
            res.replying_macs,
            vec!["aa:bb:cc:11:22:33", "de:ad:be:ef:00:01"]
        );
    }

    #[test]
    fn test_parse_ip_monitor_line() {
        let ev1 = parse_ip_monitor_line("default via 10.0.0.1 dev wlan0 proto dhcp");
        assert!(matches!(ev1, Some(NetlinkEvent::RouteOrAddrChanged(_))));

        let ev_addr = parse_ip_monitor_line(
            "3: wlan0    inet 10.0.0.88/24 brd 10.0.0.255 scope global dynamic wlan0",
        );
        assert!(matches!(ev_addr, Some(NetlinkEvent::RouteOrAddrChanged(_))));

        let ev2 =
            parse_ip_monitor_line("192.168.1.1 dev wlan0 lladdr aa:bb:cc:11:22:33 REACHABLE");
        assert_eq!(
            ev2,
            Some(NetlinkEvent::NeighChanged {
                ip: "192.168.1.1".to_string(),
                dev: "wlan0".to_string(),
                mac: Some("aa:bb:cc:11:22:33".to_string()),
                state: "REACHABLE".to_string(),
            })
        );
    }
}
