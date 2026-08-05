***Terminal 1: Daemon Launch & Live Debug Logs***
*Step 1: Cleanup Stale Interfaces & Sockets*


sudo ip link delete wg0 2>/dev/null
sudo killall -9 wireguard-go 2>/dev/null
sudo rm -rf /var/run/wireguard/wg0.sock /var/run/wireguard/wg0.name

*Step 2: Set Environment Variables & Launch wireguard-go (Terminal 1)*

cd ~/wg-go-app/wireguard-go
export SCION_ENABLED=true
export SCION_BOOTSTRAP_URL=http://141.44.25.151:8041
export SCION_CONFIG_DIR=/home/jonas/wg-go-app/wireguard-go
export LOG_LEVEL=debug
sudo -E ./wireguard-go -f wg0

----------------------------------------------------------------------------------------

***Terminal 2: Configuration & Testing***
# Step 1: Apply test2.conf & Assign IPs*

# Load test2.conf into wg0
sudo wg setconf wg0 test2.conf

# Assign Tunnel IP addresses
sudo ip addr add 10.44.25.71/32 dev wg0
sudo ip -6 addr add fd42:42:42::71/128 dev wg0

# Bring the interface UP
sudo ip link set dev wg0 mtu 1280
sudo ip link set wg0 up

# Step 2: Configure Peer & AllowedIPs

# Ensure target host (141.44.25.150) and SCION prefix (fc00::/8) are allowed
sudo wg set wg0 peer xQhVOXsX+d1MdT2jCzjShWV+cQZ3DqjRnhGlYQd7UC0= \
  allowed-ips 10.44.25.0/24,141.44.25.150/32,141.44.25.151/32,fc00::/8


# Step 3: Add Kernel Routes

# IPv4 routes for legacy internet test
sudo ip route replace 10.44.25.0/24 dev wg0 src 10.44.25.71
sudo ip route replace 141.44.25.150/32 dev wg0 src 10.44.25.71
sudo ip route replace 141.44.25.151/32 dev wg0 src 10.44.25.71

# IPv6 route for translated SCION traffic
sudo ip -6 route replace fc00::/8 dev wg0



***Step 4: Execute Connectivity Tests (in Terminal 2)***
Test A: Legacy IP Webpage via Tunnel

curl -v http://141.44.25.150/ -H "Host: welcome.scion.host"

# tested with this got full handshake
curl -v -k https://welcome.scion.host/ --resolve welcome.scion.host:443:141.44.25.150

Expected Output:
You are currently accessing this page on the legacy Internet.


Test B: SCION-Native Webpage via Translation

curl -v -k --resolve welcome.scion.host:443:[fc04:7800:4a00::ffff:8d2c:1996] https://welcome.scion.host/

Expected Output:
You are accessing this page via SCION!
