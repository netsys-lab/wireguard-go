curl -v -6 "http://[fc04:7800:4a00::ffff:8d2c:1996]/" -H "Host: welcome.scion.host"
# For standard HTTP
curl -v --resolve welcome.scion.host:80:[fc04:7800:4a00::ffff:8d2c:1996] http://welcome.scion.host/
# For HTTPS
curl -v --resolve welcome.scion.host:443:[fc04:7800:4a00::ffff:8d2c:1996] https://welcome.scion.host/
curl -v --resolve "welcome.scion.host:80:[$(python scion2ip.py 71-2:0:4a 0 0 141.44.25.150)]" http://welcome.scion.host/
###
curl -v --resolve welcome.scion.host:80:[fc04:7800:4a00::ffff:8d2c:1996] http://welcome.scion.host/
curl -v --interface wg0 --resolve welcome.scion.host:80:[fc04:7800:4a00::ffff:8d2c:1996] http://welcome.scion.host/

###
curl -v --resolve welcome.scion.host:80:[fc04:7800:4a00::ffff:8d2c:1996] http://welcome.scion.host/
curl -i --resolve welcome.scion.host:80:[fc04:7800:4a00::ffff:8d2c:1996] http://welcome.scion.host/
###


################################VM output###############################

# 1. Apply WireGuard interface configuration
sudo wg setconf wg0 test2.conf

# 2. Assign tunnel IP addresses
sudo ip addr add 10.44.25.70/32 dev wg0
sudo ip -6 addr add fd42:42:42::70/128 dev wg0

# 3. Bring up the interface
sudo ip link set wg0 up

# 4. Configure WireGuard AllowedIPs (MUST include target 141.44.25.150/32 & SCION prefix fc00::/8)
sudo wg set wg0 peer xQhVOXsX+d1MdT2jCzjShWV+cQZ3DqjRnhGlYQd7UC0= \
  allowed-ips 10.44.25.0/24,141.44.25.150/32,141.44.25.151/32,fc00::/8

# 5. OS Routes for IPv4 (Legacy IP test via tunnel)
sudo ip route replace 10.44.25.0/24 dev wg0 src 10.44.25.70
sudo ip route replace 141.44.25.150/32 dev wg0 src 10.44.25.70

# 6. OS Routes for IPv6 (SCION translated test via tunnel)
sudo ip -6 route replace fc00::/8 dev wg0




# Verify route path
ip route get 141.44.25.150

# Curl the legacy site
curl -v http://141.44.25.150/ -H "Host: welcome.scion.host"

Expected Result:
You are currently accessing this page on the legacy Internet.


# Verify IPv6 route path (Must say 'dev wg0')
ip -6 route get fc04:7800:4a00::ffff:8d2c:1996

# Curl the SCION host over translated IPv6 on port 443
curl -v -k --resolve welcome.scion.host:443:[fc04:7800:4a00::ffff:8d2c:1996] https://welcome.scion.host/

expected result:
You are accessing this page via SCION!