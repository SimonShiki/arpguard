use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

pub const DEFAULT_ETHERCODES_PATH: &str = "/var/lib/arpwatch/ethercodes.dat";

/// Normalizes any MAC string (e.g. "0:8:e1:1:2:d6" or "00:08:E1:01:02:D6")
/// into canonical lowercase zero-padded format "00:08:e1:01:02:d6".
pub fn normalize_mac(mac: &str) -> String {
    let trimmed = mac.trim().to_ascii_lowercase();
    let parts: Vec<&str> = trimmed.split(':').collect();
    if parts.len() != 6 {
        return trimmed;
    }
    let mut out = String::with_capacity(17);
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        if part.len() == 1 {
            out.push('0');
        }
        out.push_str(part);
    }
    out
}

/// Converts the first 3 octets of a MAC address into compact arpwatch `ethercodes.dat` key format
/// (e.g. "00:00:0c:11:22:33" -> "0:0:c").
pub fn mac_to_compact_oui(mac: &str) -> Option<String> {
    let parts: Vec<&str> = mac.trim().split(':').collect();
    if parts.len() < 3 {
        return None;
    }
    let b0 = u8::from_str_radix(parts[0], 16).ok()?;
    let b1 = u8::from_str_radix(parts[1], 16).ok()?;
    let b2 = u8::from_str_radix(parts[2], 16).ok()?;
    Some(format!("{:x}:{:x}:{:x}", b0, b1, b2))
}

/// Checks if a MAC address is an RFC 5798 VRRP / HSRP / CARP virtual router MAC.
/// Enterprise and campus networks legitimately switch or share these virtual MACs.
pub fn is_virtual_router_mac(mac: &str) -> bool {
    let norm = normalize_mac(mac);
    norm.starts_with("00:00:5e:00:01:")
        || norm.starts_with("00:00:5e:00:02:")
        || norm.starts_with("00:00:0c:07:ac:")
        || norm.starts_with("00:00:0c:9f:f")
}

#[derive(Default, Clone)]
pub struct OuiDb {
    vendors: HashMap<String, String>,
}

impl OuiDb {
    pub fn load_from_file(path: &Path) -> Self {
        let mut vendors = HashMap::new();
        if let Ok(file) = File::open(path) {
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((prefix, vendor)) = line.split_once('\t') {
                    vendors.insert(
                        prefix.trim().to_ascii_lowercase(),
                        vendor.trim().to_string(),
                    );
                }
            }
        }
        Self { vendors }
    }

    pub fn load_default() -> Self {
        Self::load_from_file(Path::new(DEFAULT_ETHERCODES_PATH))
    }

    pub fn lookup(&self, mac: &str) -> Option<String> {
        let key = mac_to_compact_oui(mac)?;
        self.vendors.get(&key).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_mac_and_oui() {
        assert_eq!(normalize_mac("0:8:E1:1:2:d6"), "00:08:e1:01:02:d6");
        assert_eq!(
            mac_to_compact_oui("00:00:0c:11:22:33").as_deref(),
            Some("0:0:c")
        );
        assert!(is_virtual_router_mac("00:00:5e:00:01:01"));
        assert!(!is_virtual_router_mac("de:ad:be:ef:00:01"));
    }
}
