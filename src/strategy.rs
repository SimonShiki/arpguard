use crate::arpwatch::{ArpDatRecord, ArpEvent, ArpEventKind};
use crate::network::NetworkContext;
use crate::oui::{is_virtual_router_mac, normalize_mac};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttackKind {
    /// Another device on the LAN sent an ARP packet claiming the default gateway's IP
    /// while using a MAC address already known to belong to another non-gateway LAN IP.
    GatewaySpoofByKnownPeer,
    /// The default gateway's MAC changed/flipped while the verified gateway MAC is still alive
    /// on the wire (or multiple MACs replied simultaneously to an active ARP probe).
    GatewayArpSpoof,
    /// Ethernet frame source MAC did not match the inner ARP Sender Hardware Address (SHA).
    EthernetMismatch,
    /// Another device on the LAN claimed this machine's own local IP address.
    IpConflict,
    /// Rapid flip-flop on a LAN peer IP (potential peer-to-peer MITM spoofing).
    PeerArpFlipFlop,
}

impl AttackKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GatewaySpoofByKnownPeer => "gateway_spoof_by_known_peer",
            Self::GatewayArpSpoof => "gateway_arp_spoof",
            Self::EthernetMismatch => "ethernet_mismatch",
            Self::IpConflict => "ip_conflict",
            Self::PeerArpFlipFlop => "peer_arp_flip_flop",
        }
    }

    pub fn title(&self) -> &'static str {
        match self {
            Self::GatewaySpoofByKnownPeer => "CRITICAL: Gateway ARP Spoofing (Known LAN Peer)",
            Self::GatewayArpSpoof => "CRITICAL: Gateway ARP Spoofing Detected",
            Self::EthernetMismatch => "HIGH: Forged ARP Frame (Ethernet Mismatch)",
            Self::IpConflict => "HIGH: Local IP Address Conflict Detected",
            Self::PeerArpFlipFlop => "WARNING: LAN Peer ARP Flip-Flop Detected",
        }
    }

    pub fn is_critical_gateway_or_self(&self) -> bool {
        matches!(
            self,
            Self::GatewaySpoofByKnownPeer
                | Self::GatewayArpSpoof
                | Self::EthernetMismatch
                | Self::IpConflict
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackVerdict {
    pub kind: AttackKind,
    pub target_ip: String,
    pub attacker_mac: String,
    pub legitimate_mac: Option<String>,
    pub attacker_known_ips: Vec<String>,
    pub attacker_vendor: Option<String>,
    pub attacker_hostname: Option<String>,
    pub mitigation_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StrategyDecision {
    /// Normal ARP activity; no action needed.
    Normal,
    /// Initial gateway MAC learned and should be pinned in kernel neighbor table.
    PinInitialGateway { gw_ip: String, gw_mac: String },
    /// Old gateway MAC is no longer alive on L2 and new MAC is verified; seamlessly update pin
    /// so the user's surfing experience is never interrupted.
    LegitimateGatewayMigration {
        gw_ip: String,
        old_mac: String,
        new_mac: String,
    },
    /// Confirmed ARP attack; keep real gateway pinned (or defend local IP) and trigger forensics/notification.
    AttackDetected(AttackVerdict),
}

/// Maintains the live ARP state for the current network and applies the Huorong-inspired
/// "Surfing First" protection strategy.
pub struct ProtectionEngine {
    pub ctx: NetworkContext,
    /// ip -> currently observed MAC
    pub ip_to_mac: HashMap<String, String>,
    /// mac -> set of non-zero IPs observed using this MAC
    pub mac_to_ips: HashMap<String, HashSet<String>>,
    /// ip -> observed hostname from arpwatch
    pub ip_to_hostname: HashMap<String, String>,
}

impl ProtectionEngine {
    pub fn new(ctx: NetworkContext) -> Self {
        let mut engine = Self {
            ctx,
            ip_to_mac: HashMap::new(),
            mac_to_ips: HashMap::new(),
            ip_to_hostname: HashMap::new(),
        };
        if let (Some(gw_ip), Some(gw_mac)) = (
            engine.ctx.gateway_ip.clone(),
            engine.ctx.verified_gateway_mac.clone(),
        ) {
            engine.record_mapping(&gw_ip, &gw_mac, None);
        }
        engine
    }

    pub fn ingest_arp_dat(&mut self, records: &[ArpDatRecord]) {
        for rec in records {
            if rec.ip != "0.0.0.0" {
                self.record_mapping(&rec.ip, &rec.mac, rec.hostname.as_deref());
            }
        }
    }

    /// Updates local IP and MAC when DHCP renews or changes the host's address on the same network,
    /// ensuring IP conflict detection and defense never act on a stale lease.
    pub fn update_local_identity(
        &mut self,
        new_local_ip: Option<String>,
        new_local_mac: Option<String>,
    ) {
        if let (Some(old_ip), Some(old_mac)) =
            (self.ctx.local_ip.as_deref(), self.ctx.local_mac.as_deref())
        {
            let norm_old_mac = normalize_mac(old_mac);
            if Some(old_ip) != new_local_ip.as_deref() {
                if let Some(ips) = self.mac_to_ips.get_mut(&norm_old_mac) {
                    ips.remove(old_ip);
                }
            }
        }
        self.ctx.local_ip = new_local_ip;
        self.ctx.local_mac = new_local_mac.map(|m| normalize_mac(&m));
    }

    pub fn record_mapping(&mut self, ip: &str, mac: &str, hostname: Option<&str>) {
        let norm_mac = normalize_mac(mac);
        self.ip_to_mac.insert(ip.to_string(), norm_mac.clone());
        self.mac_to_ips
            .entry(norm_mac)
            .or_default()
            .insert(ip.to_string());
        if let Some(h) = hostname {
            if !h.is_empty() && h != "<unknown>" {
                self.ip_to_hostname.insert(ip.to_string(), h.to_string());
            }
        }
    }

    /// Returns all known non-gateway, non-local IPs associated with `mac`.
    pub fn known_non_gateway_ips_for_mac(&self, mac: &str) -> Vec<String> {
        let norm_mac = normalize_mac(mac);
        let gw_ip = self.ctx.gateway_ip.as_deref();
        let local_ip = self.ctx.local_ip.as_deref();
        let mut ips: Vec<String> = self
            .mac_to_ips
            .get(&norm_mac)
            .into_iter()
            .flatten()
            .filter(|ip| {
                Some(ip.as_str()) != gw_ip
                    && Some(ip.as_str()) != local_ip
                    && ip.as_str() != "0.0.0.0"
            })
            .cloned()
            .collect();
        ips.sort();
        ips
    }

    /// Evaluates an incoming `ArpEvent`.
    /// `probe_gateway_macs` is a closure called only when disambiguating a gateway MAC change
    /// (`Fn(&str, &str) -> Vec<String>` returning all MACs that actively reply to `arping` for `gw_ip`).
    pub fn evaluate<F>(&mut self, event: &ArpEvent, probe_gateway_macs: F) -> StrategyDecision
    where
        F: FnOnce(&str, &str) -> Vec<String>,
    {
        let ev_mac = normalize_mac(&event.mac);
        let ev_old_mac = event.old_mac.as_deref().map(normalize_mac);

        if let Some(h) = &event.hostname {
            self.ip_to_hostname.insert(event.ip.clone(), h.clone());
        }

        // 1. Check for Local IP Conflict (Huorong IP Conflict Defense)
        if let (Some(local_ip), Some(local_mac)) =
            (self.ctx.local_ip.as_deref(), self.ctx.local_mac.as_deref())
        {
            if event.ip == local_ip && ev_mac != normalize_mac(local_mac) {
                let known_ips = self.known_non_gateway_ips_for_mac(&ev_mac);
                return StrategyDecision::AttackDetected(AttackVerdict {
                    kind: AttackKind::IpConflict,
                    target_ip: local_ip.to_string(),
                    attacker_mac: ev_mac,
                    legitimate_mac: Some(normalize_mac(local_mac)),
                    attacker_known_ips: known_ips,
                    attacker_vendor: event.vendor.clone(),
                    attacker_hostname: event.hostname.clone(),
                    mitigation_action: format!(
                        "Defended local IP {} via gratuitous ARP re-assertion (local MAC {})",
                        local_ip, local_mac
                    ),
                });
            }
        }

        // 2. Check for Ethernet Frame / ARP Payload Mismatch (`ethernet mismatch`)
        if event.kind == ArpEventKind::EthernetMismatch {
            let known_ips = self.known_non_gateway_ips_for_mac(&ev_mac);
            let mitigation = match (&self.ctx.gateway_ip, &self.ctx.verified_gateway_mac) {
                (Some(gw_ip), Some(gw_mac)) => format!(
                    "Gateway {} remains locked to verified MAC {} (nud permanent)",
                    gw_ip, gw_mac
                ),
                _ => "Logged malformed ARP header mismatch".to_string(),
            };
            return StrategyDecision::AttackDetected(AttackVerdict {
                kind: AttackKind::EthernetMismatch,
                target_ip: event.ip.clone(),
                attacker_mac: ev_mac,
                legitimate_mac: self.ctx.verified_gateway_mac.clone().or(ev_old_mac),
                attacker_known_ips: known_ips,
                attacker_vendor: event.vendor.clone(),
                attacker_hostname: event.hostname.clone(),
                mitigation_action: mitigation,
            });
        }

        // 3. Check if this event affects the Default Gateway IP
        if let Some(gw_ip) = self.ctx.gateway_ip.clone() {
            if event.ip == gw_ip {
                // Case 3a: We didn't have a verified gateway MAC yet -> learn & pin on first observation
                let Some(verified_gw_mac) = self.ctx.verified_gateway_mac.clone() else {
                    self.ctx.verified_gateway_mac = Some(ev_mac.clone());
                    self.record_mapping(&gw_ip, &ev_mac, event.hostname.as_deref());
                    return StrategyDecision::PinInitialGateway {
                        gw_ip,
                        gw_mac: ev_mac,
                    };
                };

                // Case 3b: The event reports the REAL verified gateway MAC again
                // (e.g., `flip flop` where `mac == verified_gw_mac` and `old_mac == attacker_mac`!)
                if ev_mac == verified_gw_mac {
                    if let Some(old_m) = ev_old_mac {
                        if old_m != verified_gw_mac && !is_virtual_router_mac(&old_m) {
                            let known_ips = self.known_non_gateway_ips_for_mac(&old_m);
                            let kind = if !known_ips.is_empty() {
                                AttackKind::GatewaySpoofByKnownPeer
                            } else {
                                AttackKind::GatewayArpSpoof
                            };
                            return StrategyDecision::AttackDetected(AttackVerdict {
                                kind,
                                target_ip: gw_ip.clone(),
                                attacker_mac: old_m,
                                legitimate_mac: Some(verified_gw_mac.clone()),
                                attacker_known_ips: known_ips,
                                attacker_vendor: event.old_vendor.clone(),
                                attacker_hostname: None,
                                mitigation_action: format!(
                                    "Preserved kernel static ARP lock for gateway {} -> {}",
                                    gw_ip, verified_gw_mac
                                ),
                            });
                        }
                    }
                    return StrategyDecision::Normal;
                }

                // Case 3c: `ev_mac != verified_gw_mac` (A different MAC is claiming the Gateway IP!)
                // First, allow RFC 5798 VRRP/HSRP virtual router MAC transitions seamlessly.
                if is_virtual_router_mac(&ev_mac) || is_virtual_router_mac(&verified_gw_mac) {
                    let old_mac = verified_gw_mac;
                    self.ctx.verified_gateway_mac = Some(ev_mac.clone());
                    self.record_mapping(&gw_ip, &ev_mac, event.hostname.as_deref());
                    return StrategyDecision::LegitimateGatewayMigration {
                        gw_ip,
                        old_mac,
                        new_mac: ev_mac,
                    };
                }

                // Second, check if `ev_mac` was ALREADY seen as another non-gateway LAN peer IP!
                // In MITM tools (ettercap/arpspoof/bettercap), the attacker's NIC MAC already belongs
                // to their client IP on the subnet.
                let peer_ips = self.known_non_gateway_ips_for_mac(&ev_mac);
                if !peer_ips.is_empty() {
                    let peer_hostname = peer_ips
                        .iter()
                        .find_map(|ip| self.ip_to_hostname.get(ip).cloned())
                        .or_else(|| event.hostname.clone());
                    return StrategyDecision::AttackDetected(AttackVerdict {
                        kind: AttackKind::GatewaySpoofByKnownPeer,
                        target_ip: gw_ip.clone(),
                        attacker_mac: ev_mac,
                        legitimate_mac: Some(verified_gw_mac.clone()),
                        attacker_known_ips: peer_ips,
                        attacker_vendor: event.vendor.clone(),
                        attacker_hostname: peer_hostname,
                        mitigation_action: format!(
                            "Blocked gateway takeover; enforced permanent ARP lock {} -> {}",
                            gw_ip, verified_gw_mac
                        ),
                    });
                }

                // Third ("Surfing First" Disambiguation):
                // Probe the gateway IP on L2 to check if the old `verified_gw_mac` is still alive
                // or if multiple MACs reply simultaneously.
                // - Positively confirmed attack: the old gateway MAC still replies on L2, OR 2+ distinct MACs
                //   reply simultaneously (ARP race).
                // - Otherwise (only the new MAC replies, OR the probe times out/fails so the old gateway MAC
                //   could not be confirmed alive): prioritize uninterrupted user surfing by migrating to `ev_mac`
                //   rather than locking a potentially dead gateway or blocking the new gateway in arptables.
                let replying_macs = probe_gateway_macs(&self.ctx.iface, &gw_ip);
                let old_still_alive = replying_macs.iter().any(|m| m == &verified_gw_mac);
                let multiple_replies = replying_macs.len() > 1;

                if !old_still_alive && !multiple_replies {
                    let old_mac = verified_gw_mac;
                    self.ctx.verified_gateway_mac = Some(ev_mac.clone());
                    self.record_mapping(&gw_ip, &ev_mac, event.hostname.as_deref());
                    return StrategyDecision::LegitimateGatewayMigration {
                        gw_ip,
                        old_mac,
                        new_mac: ev_mac,
                    };
                }

                // Confirmed Gateway ARP Spoofing (old gateway is still alive on L2 or 2+ MACs replied):
                return StrategyDecision::AttackDetected(AttackVerdict {
                    kind: AttackKind::GatewayArpSpoof,
                    target_ip: gw_ip.clone(),
                    attacker_mac: ev_mac,
                    legitimate_mac: Some(verified_gw_mac.clone()),
                    attacker_known_ips: peer_ips,
                    attacker_vendor: event.vendor.clone(),
                    attacker_hostname: event.hostname.clone(),
                    mitigation_action: format!(
                        "Protected gateway {} locked to real MAC {} (ignored spoofed ARP)",
                        gw_ip, verified_gw_mac
                    ),
                });
            }
        }

        // 4. Non-gateway peer events: record mapping and check for rapid peer flip-flop
        self.record_mapping(&event.ip, &ev_mac, event.hostname.as_deref());

        if matches!(
            event.kind,
            ArpEventKind::FlipFlop | ArpEventKind::ReusedOldEthernetAddress
        ) {
            // Only flag rapid flip-flops (< 120 seconds) on non-gateway peers to avoid DHCP lease reuse noise
            if event.delta_seconds.unwrap_or(0) <= 120 {
                let known_ips = self.known_non_gateway_ips_for_mac(&ev_mac);
                return StrategyDecision::AttackDetected(AttackVerdict {
                    kind: AttackKind::PeerArpFlipFlop,
                    target_ip: event.ip.clone(),
                    attacker_mac: ev_mac,
                    legitimate_mac: ev_old_mac,
                    attacker_known_ips: known_ips,
                    attacker_vendor: event.vendor.clone(),
                    attacker_hostname: event.hostname.clone(),
                    mitigation_action:
                        "Gateway remains pinned; logged suspicious peer ARP flip-flop".to_string(),
                });
            }
        }

        StrategyDecision::Normal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_context() -> NetworkContext {
        NetworkContext {
            iface: "wlan0".to_string(),
            gateway_ip: Some("192.168.1.1".to_string()),
            verified_gateway_mac: Some("aa:bb:cc:11:22:33".to_string()),
            local_ip: Some("192.168.1.100".to_string()),
            local_mac: Some("11:22:33:aa:bb:cc".to_string()),
            ssid: Some("Campus_WiFi".to_string()),
            network_id: "wlan0_Campus_WiFi_192.168.1.1".to_string(),
        }
    }

    #[test]
    fn test_gateway_spoof_by_known_peer() {
        let mut engine = ProtectionEngine::new(sample_context());
        // Attacker first appears normally at 192.168.1.50
        let ev_peer = ArpEvent {
            kind: ArpEventKind::NewStation,
            ip: "192.168.1.50".to_string(),
            mac: "de:ad:be:ef:00:01".to_string(),
            old_mac: None,
            vendor: None,
            old_vendor: None,
            hostname: Some("kali-laptop".to_string()),
            delta_seconds: None,
            raw_summary: String::new(),
        };
        assert_eq!(
            engine.evaluate(&ev_peer, |_, _| vec![]),
            StrategyDecision::Normal
        );

        // Now attacker spoofs gateway 192.168.1.1
        let ev_spoof = ArpEvent {
            kind: ArpEventKind::ChangedEthernetAddress,
            ip: "192.168.1.1".to_string(),
            mac: "de:ad:be:ef:00:01".to_string(),
            old_mac: Some("aa:bb:cc:11:22:33".to_string()),
            vendor: None,
            old_vendor: None,
            hostname: None,
            delta_seconds: Some(5),
            raw_summary: String::new(),
        };
        let decision = engine.evaluate(&ev_spoof, |_, _| vec![]);
        match decision {
            StrategyDecision::AttackDetected(verdict) => {
                assert_eq!(verdict.kind, AttackKind::GatewaySpoofByKnownPeer);
                assert_eq!(verdict.attacker_mac, "de:ad:be:ef:00:01");
                assert_eq!(verdict.attacker_known_ips, vec!["192.168.1.50"]);
                assert_eq!(verdict.attacker_hostname.as_deref(), Some("kali-laptop"));
                assert_eq!(
                    verdict.legitimate_mac.as_deref(),
                    Some("aa:bb:cc:11:22:33")
                );
            }
            other => panic!("Expected AttackDetected, got {:?}", other),
        }
    }

    #[test]
    fn test_legitimate_gateway_migration_when_old_gateway_offline() {
        let mut engine = ProtectionEngine::new(sample_context());
        let ev_change = ArpEvent {
            kind: ArpEventKind::ChangedEthernetAddress,
            ip: "192.168.1.1".to_string(),
            mac: "aa:bb:cc:99:88:77".to_string(),
            old_mac: Some("aa:bb:cc:11:22:33".to_string()),
            vendor: None,
            old_vendor: None,
            hostname: None,
            delta_seconds: Some(30),
            raw_summary: String::new(),
        };
        // Active probe reports ONLY the new router MAC is alive on the wire
        let decision =
            engine.evaluate(&ev_change, |_, _| vec!["aa:bb:cc:99:88:77".to_string()]);
        assert_eq!(
            decision,
            StrategyDecision::LegitimateGatewayMigration {
                gw_ip: "192.168.1.1".to_string(),
                old_mac: "aa:bb:cc:11:22:33".to_string(),
                new_mac: "aa:bb:cc:99:88:77".to_string(),
            }
        );
        assert_eq!(
            engine.ctx.verified_gateway_mac.as_deref(),
            Some("aa:bb:cc:99:88:77")
        );
    }

    #[test]
    fn test_failed_gateway_probe_prioritizes_surfing_first() {
        let mut engine = ProtectionEngine::new(sample_context());
        let ev_change = ArpEvent {
            kind: ArpEventKind::ChangedEthernetAddress,
            ip: "192.168.1.1".to_string(),
            mac: "aa:bb:cc:99:88:77".to_string(),
            old_mac: Some("aa:bb:cc:11:22:33".to_string()),
            vendor: None,
            old_vendor: None,
            hostname: None,
            delta_seconds: Some(30),
            raw_summary: String::new(),
        };
        // Simulate failed/timed-out arping returning empty list: must NOT false-alarm or block new gateway
        let decision = engine.evaluate(&ev_change, |_, _| vec![]);
        assert_eq!(
            decision,
            StrategyDecision::LegitimateGatewayMigration {
                gw_ip: "192.168.1.1".to_string(),
                old_mac: "aa:bb:cc:11:22:33".to_string(),
                new_mac: "aa:bb:cc:99:88:77".to_string(),
            }
        );

        // Conversely, if the old gateway MAC still replies to the probe, it IS detected as GatewayArpSpoof
        let ev_spoof = ArpEvent {
            kind: ArpEventKind::ChangedEthernetAddress,
            ip: "192.168.1.1".to_string(),
            mac: "de:ad:be:ef:00:55".to_string(),
            old_mac: Some("aa:bb:cc:99:88:77".to_string()),
            vendor: None,
            old_vendor: None,
            hostname: None,
            delta_seconds: Some(2),
            raw_summary: String::new(),
        };
        let decision2 =
            engine.evaluate(&ev_spoof, |_, _| vec!["aa:bb:cc:99:88:77".to_string()]);
        assert!(matches!(
            decision2,
            StrategyDecision::AttackDetected(AttackVerdict {
                kind: AttackKind::GatewayArpSpoof,
                ..
            })
        ));
    }

    #[test]
    fn test_update_local_identity_on_dhcp_renewal() {
        let mut engine = ProtectionEngine::new(sample_context());
        engine.update_local_identity(
            Some("192.168.1.150".to_string()),
            Some("11:22:33:aa:bb:cc".to_string()),
        );
        // Another device taking our old IP 192.168.1.100 must no longer trigger IpConflict
        let ev_old_ip = ArpEvent {
            kind: ArpEventKind::ChangedEthernetAddress,
            ip: "192.168.1.100".to_string(),
            mac: "de:ad:be:ef:00:99".to_string(),
            old_mac: Some("11:22:33:aa:bb:cc".to_string()),
            vendor: None,
            old_vendor: None,
            hostname: None,
            delta_seconds: Some(10),
            raw_summary: String::new(),
        };
        assert_eq!(
            engine.evaluate(&ev_old_ip, |_, _| vec![]),
            StrategyDecision::Normal
        );
    }

    #[test]
    fn test_local_ip_conflict_detected() {
        let mut engine = ProtectionEngine::new(sample_context());
        let ev_conflict = ArpEvent {
            kind: ArpEventKind::ChangedEthernetAddress,
            ip: "192.168.1.100".to_string(),
            mac: "de:ad:be:ef:00:99".to_string(),
            old_mac: Some("11:22:33:aa:bb:cc".to_string()),
            vendor: None,
            old_vendor: None,
            hostname: None,
            delta_seconds: Some(2),
            raw_summary: String::new(),
        };
        let decision = engine.evaluate(&ev_conflict, |_, _| vec![]);
        match decision {
            StrategyDecision::AttackDetected(v) => {
                assert_eq!(v.kind, AttackKind::IpConflict);
                assert_eq!(v.attacker_mac, "de:ad:be:ef:00:99");
            }
            other => panic!("Expected IpConflict, got {:?}", other),
        }
    }
}
