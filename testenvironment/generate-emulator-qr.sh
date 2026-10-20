#!/usr/bin/env bash
set -e

VM_IP=$1

if [ -z "$VM_IP" ]; then
    echo "Fehler: VM_IP muss als Parameter übergeben werden."
    exit 1
fi

# Falls qrencode fehlt, installieren
if ! command -v qrencode &> /dev/null; then
    echo "Installiere qrencode..."
    sudo apt-get update && sudo apt-get install -y qrencode
fi

# Schlüssel aus der Testumgebung auslesen
CLIENT_PRIV=$(cat .runtime/keys/client_private)
SERVER_PUB=$(cat .runtime/keys/server_public)

# Config-Datei im SCION-Format generieren
cat <<EOF > scion-emulator.conf
[Interface]
# TunnelMode = SCION
# BootstrapURL = http://10.0.0.1:8042
PrivateKey = $CLIENT_PRIV
Address = 10.0.0.2/24, 2001:db8:44:25::70/128

[Peer]
PublicKey = $SERVER_PUB
Endpoint = ${VM_IP}:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

echo "Konfiguration 'scion-emulator.conf' wurde erstellt."

# QR-Code als PNG-Bild speichern (viel kleiner und besser scannbar)
qrencode -o emulator-qr.png < scion-emulator.conf

echo "Fertig! QR-Code wurde als 'emulator-qr.png' gespeichert."
echo "Öffne das Bild z.B. mit: xdg-open emulator-qr.png"
