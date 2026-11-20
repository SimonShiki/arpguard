use crate::arpwatch::ArpDatRecord;
use crate::network::list_kernel_neighbors;
use crate::oui::{normalize_mac, OuiDb};
use crate::strategy::AttackVerdict;
use std::collections::HashSet;
use std::net::{SocketAddr, UdpSocket};
use std::process::Command;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForensicReport {
    pub timestamp_unix: u64,
    pub iface: String,
    pub ssid: Option<String>,
    pub attack_kind: String,
    pub attack_title: String,
    pub target_ip: String,
    pub legitimate_mac: Option<String>,
    pub attacker_mac: String,
    pub attacker_vendor: String,
    pub attacker_ips: Vec<String>,
    pub attacker_hostnames: Vec<String>,
    pub mitigation_action: String,
}

/// Collects attacker forensics (real IP, OUI vendor, multi-protocol hostnames) as quickly as possible.
pub fn collect_attacker_forensics(
    verdict: &AttackVerdict,
    iface: &str,
    ssid: Option<&str>,
    gateway_ip: Option<&str>,
    arp_dat_records: &[ArpDatRecord],
    oui_db: &OuiDb,
    enable_active_probes: bool,
) -> ForensicReport {
    let timestamp_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let attacker_mac = normalize_mac(&verdict.attacker_mac);

    // 1. Vendor OUI
    let attacker_vendor = verdict
        .attacker_vendor
        .clone()
        .or_else(|| oui_db.lookup(&attacker_mac))
        .unwrap_or_else(|| "Unknown Vendor".to_string());

    // 2. Discover Attacker's real IP(s) across in-memory state, arp.dat, and kernel neighbor table
    let mut ip_set: HashSet<String> = verdict.attacker_known_ips.iter().cloned().collect();
    let mut hostnames_set: HashSet<String> = HashSet::new();

    if let Some(h) = &verdict.attacker_hostname {
        if !h.is_empty() && h != "<unknown>" {
            hostnames_set.insert(h.clone());
        }
    }

    for rec in arp_dat_records {
        if normalize_mac(&rec.mac) == attacker_mac {
            if Some(rec.ip.as_str()) != gateway_ip
                && rec.ip != verdict.target_ip
                && rec.ip != "0.0.0.0"
            {
                ip_set.insert(rec.ip.clone());
            }
            if let Some(h) = &rec.hostname {
                if !h.is_empty() && h != "<unknown>" {
                    hostnames_set.insert(h.clone());
                }
            }
        }
    }

    if enable_active_probes {
        for (ip, mac) in list_kernel_neighbors(iface) {
            if mac == attacker_mac
                && Some(ip.as_str()) != gateway_ip
                && ip != verdict.target_ip
                && ip != "0.0.0.0"
            {
                ip_set.insert(ip);
            }
        }
    }

    // If the attacker wasSpoofing a peer or if their only seen IP is target_ip (and target_ip != gateway_ip),
    // include target_ip if we have no other IP and it's not the gateway IP.
    if ip_set.is_empty() && Some(verdict.target_ip.as_str()) != gateway_ip {
        ip_set.insert(verdict.target_ip.clone());
    }

    let mut attacker_ips: Vec<String> = ip_set.into_iter().collect();
    attacker_ips.sort();

    // 3. Multi-protocol hostname resolution for each discovered attacker IP (parallel per IP)
    if enable_active_probes {
        let mut handles = Vec::new();
        for ip in attacker_ips.iter().cloned() {
            handles.push(thread::spawn(move || resolve_hostnames_for_ip(&ip)));
        }
        for h in handles {
            if let Ok(names) = h.join() {
                for name in names {
                    hostnames_set.insert(name);
                }
            }
        }
    }

    let mut attacker_hostnames: Vec<String> = hostnames_set.into_iter().collect();
    attacker_hostnames.sort();

    ForensicReport {
        timestamp_unix,
        iface: iface.to_string(),
        ssid: ssid.map(|s| s.to_string()),
        attack_kind: verdict.kind.as_str().to_string(),
        attack_title: verdict.kind.title().to_string(),
        target_ip: verdict.target_ip.clone(),
        legitimate_mac: verdict.legitimate_mac.clone(),
        attacker_mac,
        attacker_vendor,
        attacker_ips,
        attacker_hostnames,
        mitigation_action: verdict.mitigation_action.clone(),
    }
}

/// Resolves hostnames for `ip` concurrently via:
/// 1. Raw UDP NetBIOS Node Status (`NBSTAT` port 137)
/// 2. mDNS (`avahi-resolve -a <ip>`)
/// 3. Reverse DNS (`getent hosts <ip>`)
pub fn resolve_hostnames_for_ip(ip: &str) -> Vec<String> {
    let ip_nb = ip.to_string();
    let t_nb = thread::spawn(move || query_netbios_name(&ip_nb, Duration::from_millis(350)));

    let ip_mdns = ip.to_string();
    let t_mdns = thread::spawn(move || query_avahi_mdns(&ip_mdns));

    let ip_dns = ip.to_string();
    let t_dns = thread::spawn(move || query_reverse_dns(&ip_dns));

    let mut names = Vec::new();
    if let Ok(Some(nb)) = t_nb.join() {
        names.push(format!("{} (NetBIOS)", nb));
    }
    if let Ok(Some(mdns)) = t_mdns.join() {
        names.push(format!("{} (mDNS)", mdns));
    }
    if let Ok(Some(dns)) = t_dns.join() {
        names.push(format!("{} (PTR)", dns));
    }
    names
}

/// Sends a raw 50-byte NetBIOS Node Status (`NBSTAT`) request to `<ip>:137`
/// and parses the workstation name from the response.
pub fn query_netbios_name(ip: &str, timeout: Duration) -> Option<String> {
    let addr: SocketAddr = format!("{}:137", ip).parse().ok()?;
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(timeout)).ok()?;
    sock.set_write_timeout(Some(timeout)).ok()?;

    // Standard 50-byte NBSTAT query for "*" (CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
    const NBSTAT_PACKET: [u8; 50] = [
        0x13, 0x37, // Transaction ID
        0x00, 0x00, // Flags: query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs
        0x00, 0x00, // Authority RRs
        0x00, 0x00, // Additional RRs
        0x20, // Name length: 32
        0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x00, // Null terminator
        0x00, 0x21, // Type: NBSTAT (0x0021)
        0x00, 0x01, // Class: IN (0x0001)
    ];

    sock.send_to(&NBSTAT_PACKET, addr).ok()?;
    let mut buf = [0u8; 512];
    let (len, _) = sock.recv_from(&mut buf).ok()?;
    parse_netbios_response(&buf[..len])
}

pub fn parse_netbios_response(buf: &[u8]) -> Option<String> {
    // Header(12) + Encoded Name(34) + Type(2) + Class(2) + TTL(4) + RDLENGTH(2) + NumNames(1) = 57
    if buf.len() < 57 {
        return None;
    }
    let num_names = buf[56] as usize;
    let mut offset = 57;
    for _ in 0..num_names {
        if offset + 18 > buf.len() {
            break;
        }
        let raw_name = &buf[offset..offset + 15];
        let suffix_type = buf[offset + 15];
        let flags = u16::from_be_bytes([buf[offset + 16], buf[offset + 17]]);
        let is_group = (flags & 0x8000) != 0;
        // 0x00 (Workstation Service) or 0x20 (File Server Service), unique (non-group) name
        if !is_group && (suffix_type == 0x00 || suffix_type == 0x20) {
            let name = String::from_utf8_lossy(raw_name).trim().to_string();
            if !name.is_empty() && name.chars().all(|c| !c.is_control()) {
                return Some(name);
            }
        }
        offset += 18;
    }
    None
}

fn query_avahi_mdns(ip: &str) -> Option<String> {
    let out = Command::new("/usr/bin/avahi-resolve")
        .args(["-a", ip])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let line = String::from_utf8_lossy(&out.stdout);
    let parts: Vec<&str> = line.trim().split_whitespace().collect();
    if parts.len() >= 2 {
        let host = parts[1].trim();
        if !host.is_empty() {
            return Some(host.to_string());
        }
    }
    None
}

fn query_reverse_dns(ip: &str) -> Option<String> {
    let out = Command::new("/usr/bin/getent")
        .args(["hosts", ip])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let line = String::from_utf8_lossy(&out.stdout);
    let parts: Vec<&str> = line.trim().split_whitespace().collect();
    if parts.len() >= 2 {
        let host = parts[1].trim();
        if !host.is_empty() && host != ip {
            return Some(host.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_netbios_response() {
        let mut pkt = vec![0u8; 57];
        pkt[56] = 1; // 1 name entry
        let mut entry = [b' '; 18];
        let name = b"ATTACKER-PC";
        entry[..name.len()].copy_from_slice(name);
        entry[15] = 0x00; // Workstation
        entry[16] = 0x04; // Unique active node
        entry[17] = 0x00;
        pkt.extend_from_slice(&entry);

        assert_eq!(
            parse_netbios_response(&pkt).as_deref(),
            Some("ATTACKER-PC")
        );
    }
}
