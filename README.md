# ARPGuard

ARPGuard is a lightweight Linux daemon for ARP spoofing detection, gateway protection, and local attacker identification. It pairs with `arpwatch` to monitor network changes and maintain connectivity without manual intervention.

## Features

### Gateway Protection

When a network connection is established or roamed, ARPGuard verifies the default gateway's hardware address and locks it in the system neighbor table so unsolicited ARP replies cannot overwrite it.

If a different hardware address claims the gateway IP, ARPGuard keeps the existing gateway locked to avoid connection drops while checking whether the original gateway is still reachable:

- **Confirmed spoofing**: If the original gateway still responds or multiple devices claim the address, ARPGuard retains the verified gateway mapping and can optionally block the attacker's ARP traffic.
- **Legitimate failover or roaming**: If the original gateway is no longer reachable and only the new address responds (or uses a standard virtual router address), ARPGuard updates the gateway mapping automatically.

ARPGuard also watches for local IP conflicts and re-asserts ownership of the host's address if another device claims it.

### Attacker Forensics and Alerts

When an attack is detected, ARPGuard correlates the offending hardware address with known LAN IP addresses, looks up the hardware vendor, and queries local name resolution services to identify the source host. Incidents are logged to `/var/log/arpguard/incidents.jsonl` and surfaced via desktop notifications.

## Build & Test

```bash
cargo test
cargo build --release
```

## Usage

```bash
# Monitor the active network interface (requires root or CAP_NET_ADMIN + CAP_NET_RAW)
sudo ./target/release/arpguard watch

# Optionally drop confirmed attacker ARP packets at the link layer
sudo ./target/release/arpguard watch --block-attacker

# Check current network/gateway status and recent incidents
./target/release/arpguard status

# Replay a PCAP file offline
./target/release/arpguard replay --pcap attack.pcap --gateway-ip 192.168.1.1 --local-ip 192.168.1.100
```

## Systemd Installation

```bash
sudo install -Dm755 target/release/arpguard /usr/local/bin/arpguard
sudo install -Dm644 deploy/arpguard.service /etc/systemd/system/arpguard.service
sudo install -Dm755 deploy/90-arpguard-nm-dispatcher.sh /etc/NetworkManager/dispatcher.d/90-arpguard
sudo systemctl daemon-reload
sudo systemctl enable --now arpguard.service
```
