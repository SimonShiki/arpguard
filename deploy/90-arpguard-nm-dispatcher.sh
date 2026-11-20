#!/usr/bin/env bash
# NetworkManager dispatcher hook for ARPGuard (/etc/NetworkManager/dispatcher.d/90-arpguard)
INTERFACE="$1"
ACTION="$2"

case "$ACTION" in
    up|connectivity-change|dhcp4-change)
        if systemctl is-enabled --quiet arpguard.service 2>/dev/null; then
            systemctl start arpguard.service
        fi
        ;;
esac
