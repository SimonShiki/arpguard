pub mod arpwatch;
pub mod forensics;
pub mod network;
pub mod notifier;
pub mod oui;
pub mod strategy;

use arpwatch::{ArpEvent, ArpwatchProcess};
use forensics::collect_attacker_forensics;
use network::{
    block_attacker_arp, defend_local_ip, discover_network_context, pin_gateway_mac,
    probe_arp_replies, spawn_netlink_monitor, NetlinkEvent, NetworkContext,
};
use notifier::IncidentNotifier;
use oui::{normalize_mac, OuiDb};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use strategy::{AttackKind, ProtectionEngine, StrategyDecision};

enum DaemonMessage {
    Arp(ArpEvent),
    Netlink(NetlinkEvent),
}

struct Config {
    mode: Mode,
    iface: Option<String>,
    workdir: PathBuf,
    log_file: PathBuf,
    dry_run: bool,
    block_attacker: bool,
}

enum Mode {
    Watch,
    Replay {
        pcap: PathBuf,
        gateway_ip: String,
        gateway_mac: Option<String>,
        local_ip: Option<String>,
        local_mac: Option<String>,
    },
    Status,
}

fn print_usage() {
    eprintln!(
        "\
arpguard — Tiny event-driven ARP monitor & dynamic gateway protector paired with arpwatch

USAGE:
  arpguard watch [OPTIONS]
  arpguard replay --pcap <FILE> [--gateway-ip <IP>] [--gateway-mac <MAC>] [--local-ip <IP>] [OPTIONS]
  arpguard status [OPTIONS]

OPTIONS:
  -i, --iface <IFACE>         Network interface to monitor (auto-detected from default route if omitted)
  -w, --workdir <DIR>         Runtime directory for arpwatch .dat files (default: /run/arpguard)
  -l, --log-file <PATH>       JSONL incident log file (default: /var/log/arpguard/incidents.jsonl)
      --block-attacker        Also drop attacker ARP frames via arptables on confirmed gateway spoof
      --dry-run               Do not modify kernel neighbor table or invoke desktop notify-send
  -h, --help                  Show this help message
"
    );
}

fn parse_args() -> Result<Config, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print_usage();
        std::process::exit(0);
    }

    let subcmd = args[0].as_str();
    let mut iface = None;
    let mut workdir = PathBuf::from("/run/arpguard");
    let mut log_file = PathBuf::from("/var/log/arpguard/incidents.jsonl");
    let mut dry_run = false;
    let mut block_attacker = false;

    let mut pcap = None;
    let mut gateway_ip = "192.168.1.1".to_string();
    let mut gateway_mac = None;
    let mut local_ip = None;
    let mut local_mac = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-i" | "--iface" => {
                i += 1;
                iface = Some(args.get(i).ok_or("Missing value for --iface")?.clone());
            }
            "-w" | "--workdir" => {
                i += 1;
                workdir = PathBuf::from(args.get(i).ok_or("Missing value for --workdir")?);
            }
            "-l" | "--log-file" => {
                i += 1;
                log_file = PathBuf::from(args.get(i).ok_or("Missing value for --log-file")?);
            }
            "--dry-run" => dry_run = true,
            "--block-attacker" => block_attacker = true,
            "--pcap" => {
                i += 1;
                pcap = Some(PathBuf::from(args.get(i).ok_or("Missing value for --pcap")?));
            }
            "--gateway-ip" => {
                i += 1;
                gateway_ip = args.get(i).ok_or("Missing value for --gateway-ip")?.clone();
            }
            "--gateway-mac" => {
                i += 1;
                gateway_mac = Some(normalize_mac(
                    args.get(i).ok_or("Missing value for --gateway-mac")?,
                ));
            }
            "--local-ip" => {
                i += 1;
                local_ip = Some(args.get(i).ok_or("Missing value for --local-ip")?.clone());
            }
            "--local-mac" => {
                i += 1;
                local_mac = Some(normalize_mac(
                    args.get(i).ok_or("Missing value for --local-mac")?,
                ));
            }
            other => return Err(format!("Unknown argument: {}", other)),
        }
        i += 1;
    }

    let mode = match subcmd {
        "watch" => Mode::Watch,
        "status" => Mode::Status,
        "replay" => Mode::Replay {
            pcap: pcap.ok_or("replay mode requires --pcap <FILE>")?,
            gateway_ip,
            gateway_mac,
            local_ip,
            local_mac,
        },
        other => {
            return Err(format!(
                "Unknown subcommand '{}'. Use watch, replay, or status.",
                other
            ))
        }
    };

    Ok(Config {
        mode,
        iface,
        workdir,
        log_file,
        dry_run,
        block_attacker,
    })
}

fn main() {
    let cfg = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}\n", e);
            print_usage();
            std::process::exit(1);
        }
    };

    match &cfg.mode {
        Mode::Status => run_status(&cfg),
        Mode::Replay {
            pcap,
            gateway_ip,
            gateway_mac,
            local_ip,
            local_mac,
        } => {
            if let Err(e) = run_replay(
                &cfg,
                pcap,
                gateway_ip,
                gateway_mac.clone(),
                local_ip.clone(),
                local_mac.clone(),
            ) {
                eprintln!("Replay error: {}", e);
                std::process::exit(1);
            }
        }
        Mode::Watch => {
            if let Err(e) = run_watch(&cfg) {
                eprintln!("Watch error: {}", e);
                std::process::exit(1);
            }
        }
    }
}

fn run_status(cfg: &Config) {
    println!("=== ARPGuard Network Status ===");
    match discover_network_context(cfg.iface.as_deref()) {
        Some(ctx) => {
            println!("Interface      : {}", ctx.iface);
            println!(
                "SSID / Network : {}",
                ctx.ssid.as_deref().unwrap_or("<wired/unknown>")
            );
            println!(
                "Local IP / MAC : {} / {}",
                ctx.local_ip.as_deref().unwrap_or("-"),
                ctx.local_mac.as_deref().unwrap_or("-")
            );
            println!(
                "Gateway IP     : {}",
                ctx.gateway_ip.as_deref().unwrap_or("-")
            );
            println!(
                "Gateway MAC    : {}",
                ctx.verified_gateway_mac.as_deref().unwrap_or("-")
            );
        }
        None => {
            println!("No active default route / interface detected.");
        }
    }

    if cfg.log_file.exists() {
        if let Ok(content) = fs::read_to_string(&cfg.log_file) {
            let lines: Vec<&str> = content.lines().collect();
            println!(
                "\n=== Recent Incidents ({}) [total: {}] ===",
                cfg.log_file.display(),
                lines.len()
            );
            for line in lines.iter().rev().take(5).rev() {
                println!("{}", line);
            }
        }
    } else {
        println!(
            "\nIncident log   : {} (no incidents recorded)",
            cfg.log_file.display()
        );
    }
}

fn run_replay(
    cfg: &Config,
    pcap: &Path,
    gateway_ip: &str,
    gateway_mac: Option<String>,
    local_ip: Option<String>,
    local_mac: Option<String>,
) -> Result<(), String> {
    let oui_db = OuiDb::load_default();
    let (events, records) = ArpwatchProcess::run_pcap_replay(pcap, &cfg.workdir)?;

    let ctx = NetworkContext {
        iface: cfg.iface.clone().unwrap_or_else(|| "replay0".to_string()),
        gateway_ip: Some(gateway_ip.to_string()),
        verified_gateway_mac: gateway_mac,
        local_ip,
        local_mac,
        ssid: Some("pcap-replay".to_string()),
        network_id: "pcap_replay".to_string(),
    };

    let mut engine = ProtectionEngine::new(ctx);
    let mut notifier = IncidentNotifier::new(0);
    let mut attacks = 0usize;

    for ev in &events {
        println!("[arpwatch] {}", ev.raw_summary);
        let verified_gw = engine.ctx.verified_gateway_mac.clone();
        let decision = engine.evaluate(ev, |_, _| verified_gw.into_iter().collect());

        match decision {
            StrategyDecision::Normal => {}
            StrategyDecision::PinInitialGateway { gw_ip, gw_mac } => {
                println!(
                    "[arpguard] Learned & locked initial gateway: {} -> {}",
                    gw_ip, gw_mac
                );
            }
            StrategyDecision::LegitimateGatewayMigration {
                gw_ip,
                old_mac,
                new_mac,
            } => {
                println!(
                    "[arpguard] Legitimate gateway migration: {} ({} -> {})",
                    gw_ip, old_mac, new_mac
                );
            }
            StrategyDecision::AttackDetected(verdict) => {
                attacks += 1;
                let report = collect_attacker_forensics(
                    &verdict,
                    &engine.ctx.iface,
                    engine.ctx.ssid.as_deref(),
                    engine.ctx.gateway_ip.as_deref(),
                    &records,
                    &oui_db,
                    false,
                );
                notifier.handle_incident(&report, Some(&cfg.log_file), false);
            }
        }
    }

    println!(
        "Replay complete: processed {} arpwatch events, detected {} ARP attack(s).",
        events.len(),
        attacks
    );
    Ok(())
}

fn run_watch(cfg: &Config) -> Result<(), String> {
    let oui_db = OuiDb::load_default();
    let mut ctx = discover_network_context(cfg.iface.as_deref()).ok_or_else(|| {
        "Could not detect an active network interface or default route. Specify --iface <IFACE>."
            .to_string()
    })?;

    // Verify gateway via active arping probe on startup
    verify_and_lock_gateway(&mut ctx, cfg.dry_run);

    let (tx, rx) = mpsc::channel::<DaemonMessage>();

    // Spawn arpwatch reader -> DaemonMessage::Arp
    let mut arpwatch_proc = spawn_arpwatch_bridge(&ctx, &cfg.workdir, tx.clone())?;
    let mut engine = ProtectionEngine::new(ctx.clone());
    let mut notifier = IncidentNotifier::new(10);

    // Spawn `ip -4 monitor route neigh` -> DaemonMessage::Netlink
    let (nl_tx, nl_rx) = mpsc::channel::<NetlinkEvent>();
    let _nl_child = spawn_netlink_monitor(nl_tx)?;
    {
        let tx_nl = tx.clone();
        std::thread::spawn(move || {
            for ev in nl_rx {
                let _ = tx_nl.send(DaemonMessage::Netlink(ev));
            }
        });
    }

    println!(
        "[arpguard] Watching interface '{}' (network: {}, gateway: {:?} -> {:?})",
        engine.ctx.iface,
        engine.ctx.network_id,
        engine.ctx.gateway_ip,
        engine.ctx.verified_gateway_mac
    );

    for msg in rx {
        match msg {
            DaemonMessage::Arp(ev) => {
                let iface_name = engine.ctx.iface.clone();
                let decision = engine.evaluate(&ev, |iface, gw_ip| {
                    probe_arp_replies(iface, gw_ip).replying_macs
                });

                match decision {
                    StrategyDecision::Normal => {}
                    StrategyDecision::PinInitialGateway { gw_ip, gw_mac } => {
                        println!(
                            "[arpguard] Learned initial gateway {} -> {}, pinning in kernel neighbor table",
                            gw_ip, gw_mac
                        );
                        if let Err(e) = pin_gateway_mac(&iface_name, &gw_ip, &gw_mac, cfg.dry_run) {
                            eprintln!("[arpguard] Warning: {}", e);
                        }
                    }
                    StrategyDecision::LegitimateGatewayMigration {
                        gw_ip,
                        old_mac,
                        new_mac,
                    } => {
                        println!(
                            "[arpguard] Verified legitimate gateway failover/roam on {}: {} -> {} (updating kernel pin)",
                            gw_ip, old_mac, new_mac
                        );
                        if let Err(e) = pin_gateway_mac(&iface_name, &gw_ip, &new_mac, cfg.dry_run)
                        {
                            eprintln!("[arpguard] Warning: {}", e);
                        }
                    }
                    StrategyDecision::AttackDetected(verdict) => {
                        // 1. Immediate protective countermeasure ("Surfing First")
                        if let (Some(gw_ip), Some(gw_mac)) = (
                            engine.ctx.gateway_ip.as_deref(),
                            engine.ctx.verified_gateway_mac.as_deref(),
                        ) {
                            if verdict.kind.is_critical_gateway_or_self() {
                                let _ = pin_gateway_mac(&iface_name, gw_ip, gw_mac, cfg.dry_run);
                            }
                            if cfg.block_attacker
                                && matches!(
                                    verdict.kind,
                                    AttackKind::GatewaySpoofByKnownPeer
                                        | AttackKind::GatewayArpSpoof
                                        | AttackKind::EthernetMismatch
                                )
                            {
                                block_attacker_arp(
                                    &iface_name,
                                    &verdict.attacker_mac,
                                    gw_ip,
                                    cfg.dry_run,
                                );
                            }
                        }
                        if verdict.kind == AttackKind::IpConflict {
                            if let Some(local_ip) = engine.ctx.local_ip.as_deref() {
                                defend_local_ip(&iface_name, local_ip, cfg.dry_run);
                            }
                        }

                        // 2. Flush arpwatch's arp.dat via SIGHUP and collect forensics immediately
                        let dat_records = arpwatch_proc.flush_and_read_dat();
                        engine.ingest_arp_dat(&dat_records);
                        let report = collect_attacker_forensics(
                            &verdict,
                            &engine.ctx.iface,
                            engine.ctx.ssid.as_deref(),
                            engine.ctx.gateway_ip.as_deref(),
                            &dat_records,
                            &oui_db,
                            !cfg.dry_run,
                        );
                        notifier.handle_incident(&report, Some(&cfg.log_file), !cfg.dry_run);
                    }
                }
            }
            DaemonMessage::Netlink(nl_ev) => match nl_ev {
                NetlinkEvent::RouteOrAddrChanged(_) => {
                    // Check if interface, SSID, default gateway IP, or local DHCP IP changed
                    if let Some(mut new_ctx) = discover_network_context(cfg.iface.as_deref()) {
                        if new_ctx.network_id != engine.ctx.network_id
                            || new_ctx.gateway_ip != engine.ctx.gateway_ip
                        {
                            println!(
                                "[arpguard] Network change detected ({} -> {}), re-initializing gateway protection",
                                engine.ctx.network_id, new_ctx.network_id
                            );
                            verify_and_lock_gateway(&mut new_ctx, cfg.dry_run);
                            arpwatch_proc.terminate();
                            if let Ok(new_proc) =
                                spawn_arpwatch_bridge(&new_ctx, &cfg.workdir, tx.clone())
                            {
                                arpwatch_proc = new_proc;
                            }
                            engine = ProtectionEngine::new(new_ctx);
                        } else if new_ctx.local_ip != engine.ctx.local_ip
                            || new_ctx.local_mac != engine.ctx.local_mac
                        {
                            println!(
                                "[arpguard] Local DHCP address updated on {}: {:?} -> {:?}",
                                engine.ctx.iface, engine.ctx.local_ip, new_ctx.local_ip
                            );
                            engine.update_local_identity(new_ctx.local_ip, new_ctx.local_mac);
                        }
                    }
                }
                NetlinkEvent::NeighChanged {
                    ip,
                    dev,
                    mac: Some(mac),
                    ..
                } => {
                    // If the kernel neighbor table for our gateway was somehow modified externally,
                    // immediately re-verify and restore our pinned gateway MAC.
                    if dev == engine.ctx.iface
                        && Some(ip.as_str()) == engine.ctx.gateway_ip.as_deref()
                    {
                        if let Some(verified_mac) = engine.ctx.verified_gateway_mac.as_deref() {
                            if mac != verified_mac && !oui::is_virtual_router_mac(&mac) {
                                let _ = pin_gateway_mac(&dev, &ip, verified_mac, cfg.dry_run);
                            }
                        }
                    }
                }
                _ => {}
            },
        }
    }

    Ok(())
}

fn verify_and_lock_gateway(ctx: &mut NetworkContext, dry_run: bool) {
    let Some(gw_ip) = ctx.gateway_ip.clone() else {
        return;
    };
    if !dry_run {
        let probe = probe_arp_replies(&ctx.iface, &gw_ip);
        if probe.replying_macs.len() == 1 {
            ctx.verified_gateway_mac = Some(probe.replying_macs[0].clone());
        } else if probe.replying_macs.len() > 1 {
            eprintln!(
                "[arpguard] WARNING: Multiple MACs ({:?}) replied to arping for gateway {} on join!",
                probe.replying_macs, gw_ip
            );
            if ctx.verified_gateway_mac.is_none() {
                ctx.verified_gateway_mac = Some(probe.replying_macs[0].clone());
            }
        }
    }
    if let Some(gw_mac) = ctx.verified_gateway_mac.as_deref() {
        if let Err(e) = pin_gateway_mac(&ctx.iface, &gw_ip, gw_mac, dry_run) {
            eprintln!(
                "[arpguard] Notice: could not pin gateway MAC ({}): {}",
                gw_mac, e
            );
        }
    }
}

fn spawn_arpwatch_bridge(
    ctx: &NetworkContext,
    workdir: &Path,
    tx: mpsc::Sender<DaemonMessage>,
) -> Result<ArpwatchProcess, String> {
    let (arp_tx, arp_rx) = mpsc::channel::<ArpEvent>();
    let proc = ArpwatchProcess::spawn_live(&ctx.iface, &ctx.network_id, workdir, arp_tx)?;
    std::thread::spawn(move || {
        for ev in arp_rx {
            if tx.send(DaemonMessage::Arp(ev)).is_err() {
                break;
            }
        }
    });
    Ok(proc)
}
