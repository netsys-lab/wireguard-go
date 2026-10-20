#!/usr/bin/env bash
set -e

echo "=== 1. Internen Test-Client beenden ==="
# Den WireGuard-Client stoppen, falls er läuft
sudo ./06-wireguard.sh client-down 2>/dev/null || true

echo "=== 2. VM IP-Adresse auslesen ==="
# Automatisch die IP des Host-Only Adapters (enp0s8) finden
VM_IP=$(ip -4 addr show enp0s8 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || hostname -I | awk '{print $1}')
if [ -z "$VM_IP" ]; then
    echo "Fehler: Konnte VM-IP nicht ermitteln."
    exit 1
fi
echo "Gefundene VM-IP: $VM_IP"

echo "=== 3. Routing konfigurieren ==="
# IP-Forwarding aktivieren
sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null

# Veth-Paar für die Host-Namespace-Brücke anlegen (falls noch nicht existent)
if ! ip link show veth-emu > /dev/null 2>&1; then
    sudo ip link add veth-emu type veth peer name veth-srv
    sudo ip link set veth-srv netns Server
    sudo ip addr add 172.16.0.1/24 dev veth-emu
    sudo ip link set veth-emu up
    sudo ip netns exec Server ip addr add 172.16.0.2/24 dev veth-srv
    sudo ip netns exec Server ip link set veth-srv up
fi

# Portweiterleitung (NAT) für WireGuard-Port 51820 in den Namespace
sudo iptables -t nat -C PREROUTING -p udp -d $VM_IP --dport 51820 -j DNAT --to-destination 172.16.0.2:51820 2>/dev/null || \
sudo iptables -t nat -A PREROUTING -p udp -d $VM_IP --dport 51820 -j DNAT --to-destination 172.16.0.2:51820

sudo iptables -t nat -C POSTROUTING -o veth-emu -j MASQUERADE 2>/dev/null || \
sudo iptables -t nat -A POSTROUTING -o veth-emu -j MASQUERADE

# Paketweiterleitung (FORWARD) in den Namespace explizit erlauben
sudo iptables -C FORWARD -o veth-emu -j ACCEPT 2>/dev/null || \
sudo iptables -A FORWARD -o veth-emu -j ACCEPT

sudo iptables -C FORWARD -i veth-emu -j ACCEPT 2>/dev/null || \
sudo iptables -A FORWARD -i veth-emu -j ACCEPT

sudo iptables -C FORWARD -p udp -d 172.16.0.2 --dport 51820 -j ACCEPT 2>/dev/null || \
sudo iptables -A FORWARD -p udp -d 172.16.0.2 --dport 51820 -j ACCEPT

echo "=== 4. QR-Code Skript aufrufen ==="
# Das QR-Code Skript mit der ermittelten VM_IP aufrufen
./generate-emulator-qr.sh "$VM_IP"
