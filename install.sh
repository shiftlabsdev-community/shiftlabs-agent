#!/bin/bash
set -e

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --private-key) PRIVATE_KEY="$2"; shift ;;
        --server-public-key) SERVER_PUBLIC_KEY="$2"; shift ;;
        --address) ADDRESS="$2"; shift ;;
        --endpoint) ENDPOINT="$2"; shift ;;
        --allowed-ip-subnet) ALLOWED_IP_SUBNET="$2"; shift ;;
        *) echo "Unknown parameter passed: $1"; exit 1 ;;
    esac
    shift
done

if [ -z "$PRIVATE_KEY" ] || [ -z "$SERVER_PUBLIC_KEY" ] || [ -z "$ADDRESS" ] || [ -z "$ENDPOINT" ] || [ -z "$ALLOWED_IP_SUBNET" ]; then
    echo "Missing parameters."
    exit 1
fi

WG_CONF="/etc/wireguard/wg0.conf"

echo "[+] Installing WireGuard"
apt update && apt install -y wireguard iproute2

echo "[+] Writing WireGuard config"
cat > $WG_CONF << EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = $ADDRESS
DNS = 1.1.1.1

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25

EOF

echo "[+] Enabling IP forwarding and iptables"
sysctl -w net.ipv4.ip_forward=1
iface=$(ip route get 1.1.1.1 | awk '/dev/ {print $5; exit}')
iptables -t nat -A POSTROUTING -s $ALLOWED_IP_SUBNET -o $iface -j MASQUERADE

echo "[+] Starting WireGuard"
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

echo "[+] Done. WireGuard started."
