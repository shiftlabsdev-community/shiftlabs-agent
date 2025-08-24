#!/bin/bash
# shiftlabs customer-side WireGuard installer (multi-AllowedIPs, no full-tunnel)
set -euo pipefail

# --- Helpers ---------------------------------------------------------------
need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
  fi
}

msg() { echo "[+] $*"; }

# --- Main ------------------------------------------------------------------
need_root

# Stop existing WG (idempotent)
msg "Stopping existing WireGuard (if any)"
wg-quick down wg0 2>/dev/null || true
systemctl stop wg-quick@wg0 2>/dev/null || true
rm -f /etc/wireguard/wg0.conf || true

# Parse args
PRIVATE_KEY=""
SERVER_PUBLIC_KEY=""
ADDRESS=""
ENDPOINT=""
ALLOWED_IPS=()   # multiple --allowed-ip-subnet supported

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --private-key)        PRIVATE_KEY="${2:-}"; shift ;;
    --server-public-key)  SERVER_PUBLIC_KEY="${2:-}"; shift ;;
    --address)            ADDRESS="${2:-}"; shift ;;
    --endpoint)           ENDPOINT="${2:-}"; shift ;;
    --allowed-ip-subnet)  ALLOWED_IPS+=("${2:-}"); shift ;;  # can be repeated
    *) echo "Unknown parameter: $1" >&2; exit 1 ;;
  esac
  shift
done

if [ -z "$PRIVATE_KEY" ] || [ -z "$SERVER_PUBLIC_KEY" ] || [ -z "$ADDRESS" ] || [ -z "$ENDPOINT" ] || [ "${#ALLOWED_IPS[@]}" -eq 0 ]; then
  cat >&2 <<EOF
Missing parameters.

Required:
  --private-key <str>
  --server-public-key <str>
  --address <10.200.X.Y/32>
  --endpoint <host:port>
  --allowed-ip-subnet <CIDR>   # can be passed multiple times

Example:
  --allowed-ip-subnet 10.200.0.1/32
EOF
  exit 1
fi

WG_CONF="/etc/wireguard/wg0.conf"

# Install packages
msg "Installing WireGuard and deps"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq wireguard iproute2 iptables >/dev/null

# Join AllowedIPs by comma
ALLOWED_JOINED="$(IFS=, ; echo "${ALLOWED_IPS[*]}")"

# Write config
msg "Writing WireGuard config → $WG_CONF"
umask 077
cat > "$WG_CONF" <<EOF
[Interface]
PrivateKey = ${PRIVATE_KEY}
Address = ${ADDRESS}
SaveConfig = true

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED_JOINED}
PersistentKeepalive = 25
EOF
chmod 600 "$WG_CONF"

# Enable forwarding
msg "Enabling IPv4 forwarding"
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.forwarding=1 >/dev/null

# Detect LAN egress interface (default route)
lan_if="$(ip route get 1.1.1.1 2>/dev/null | awk '/ dev / {for(i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
if [ -z "${lan_if}" ]; then
  echo "Could not detect egress interface." >&2
  exit 1
fi
msg "Detected egress interface: ${lan_if}"

# NAT/SNAT for server-originated traffic into customer LAN
# Always SNAT 10.200.0.1/32 (server WG IP) → LAN, to ensure reply path works
msg "Adding MASQUERADE rule for 10.200.0.1/32 → ${lan_if}"
iptables -t nat -C POSTROUTING -s 10.200.0.1/32 -o "${lan_if}" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -s 10.200.0.1/32 -o "${lan_if}" -j MASQUERADE

# Be nice: allow forwarding if filter policy is restrictive
msg "Ensuring FORWARD rules"
iptables -C FORWARD -i wg0 -o "${lan_if}" -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i wg0 -o "${lan_if}" -j ACCEPT
iptables -C FORWARD -i "${lan_if}" -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i "${lan_if}" -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT

# Clean old per-route entries (wg-quick usually handles routes, this is just hygiene)
msg "Cleaning old routes (if any)"
for cidr in "${ALLOWED_IPS[@]}"; do
  ip route del "$cidr" dev wg0 2>/dev/null || true
done

# Start WG
msg "Starting WireGuard"
systemctl enable wg-quick@wg0 >/dev/null
systemctl restart wg-quick@wg0

# Show status
echo
msg "WireGuard is up. Status:"
wg show || true
ip addr show wg0 || true
ip route show table main | sed -n '1,120p' || true

echo
msg "Done."
