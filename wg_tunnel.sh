#!/bin/bash

# Log Level
WIREGUARD_LOG_LEVEL_ENV="debug"  # default empty


# Namespaces
SERVER="Server"
CLIENT="Client"

# WireGuard Interface
WG_SERVER="wg-server"
WG_CLIENT="wg-client"

# IPs
WG_SERVER_IP="10.10.10.1/32"
WG_CLIENT_IP="10.10.10.2/32"
SERVER_ENDPOINT="10.0.0.1:51820"

# All Paths are from .sh location

# Paths to keys
SERVER_PRIV_KEY="./server.key"
SERVER_PUB_KEY="./server.pub"
CLIENT_PRIV_KEY="./client.key"
CLIENT_PUB_KEY="./client.pub"

# Path to wireguard-go
WIREGUARD_GO="./wireguard-go"

# Userspace version of Quickstart guide:
# https://www.wireguard.com/quickstart/

# Function to generate Server and Client keypairs
function generate_keys() {
	echo "+ Generating keys"
	wg genkey | tee $SERVER_PRIV_KEY | wg pubkey > $SERVER_PUB_KEY
	wg genkey | tee $CLIENT_PRIV_KEY | wg pubkey > $CLIENT_PUB_KEY
}

wait_for_socket() {
    for i in {1..20}; do
        [ -S "$1" ] && return 0
        sleep 0.2
    done
    echo "Error: UAPI socket $1 not found"
    exit 1
}


function start_wireguard_go() {
	echo "+ Starting wireguard-go in namespaces"
	
	which $WIREGUARD_GO

	#sudo ip netns exec $SERVER ip link add $WG_SERVER
	#sudo ip netns exec $CLIENT ip link add $WG_CLIENT

	#sudo ip netns exec $SERVER env \
	  #WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1 \
	  #LOG_LEVEL="$WIREGUARD_LOG_LEVEL_ENV" \
	  #$WIREGUARD_GO --foreground $WG_SERVER &
	#sleep 1
	
	#sudo ip netns exec $CLIENT env \
	  #WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1 \
	  #LOG_LEVEL="$WIREGUARD_LOG_LEVEL_ENV" \
	  #$WIREGUARD_GO --foreground $WG_CLIENT &
	 #sleep 1
	 
	 sudo ip netns exec $SERVER bash -c "
	  export WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1
	  export LOG_LEVEL=$WIREGUARD_LOG_LEVEL_ENV
	  $WIREGUARD_GO  $WG_SERVER
	" &
	
	sleep 1

	sudo ip netns exec $CLIENT bash -c "
	  export WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1
	  export LOG_LEVEL=$WIREGUARD_LOG_LEVEL_ENV
	  $WIREGUARD_GO --foreground $WG_CLIENT > /tmp/wg-client.log 2>&1
	" &

	sleep 3
}

function configure_interfaces() {
	echo "+ Assigning tunnel IPs and bringing up interfaces"

	sudo ip netns exec $SERVER ip addr add $WG_SERVER_IP dev $WG_SERVER
	sudo ip netns exec Server ip link set wg-server up
	sudo ip netns exec Server ip route add 10.10.10.2/32 dev wg-server
	
	sudo ip netns exec $CLIENT ip addr add $WG_CLIENT_IP dev $WG_CLIENT
	sudo ip netns exec Client ip link set wg-client up
	sudo ip netns exec Client ip route add 10.10.10.1/32 dev wg-client

}


function configure_wireguard() {
	echo "+ Configuring Wireguard peers"

	UAPI_SOCKET_SERVER="/var/run/wireguard/${WG_SERVER}.sock"
	UAPI_SOCKET_CLIENT="/var/run/wireguard/${WG_CLIENT}.sock"
	
	PRIVATE_KEY_HEX_SERVER=$(base64 -d $SERVER_PRIV_KEY | xxd -p -c 256)
	PEER_PUBLIC_KEY_HEX_SERVER=$(base64 -d $CLIENT_PUB_KEY | xxd -p -c 256)

	PRIVATE_KEY_HEX_CLIENT=$(base64 -d $CLIENT_PRIV_KEY | xxd -p -c 256)
	PEER_PUBLIC_KEY_HEX_CLIENT=$(base64 -d $SERVER_PUB_KEY | xxd -p -c 256)
	
	wait_for_socket "$UAPI_SOCKET_SERVER"
	wait_for_socket "$UAPI_SOCKET_CLIENT"
	
	echo "+ Configuring Server"
	cat << EOF | sudo socat - UNIX-CONNECT:"$UAPI_SOCKET_SERVER"
set=1
private_key=$PRIVATE_KEY_HEX_SERVER
listen_port=51820
EOF

	# Peer config (with set=1)
	cat << EOF | sudo socat - UNIX-CONNECT:"$UAPI_SOCKET_SERVER"
set=1
public_key=$PEER_PUBLIC_KEY_HEX_SERVER
allowed_ip=$WG_CLIENT_IP
endpoint=10.0.0.2:51820
persistent_keepalive_interval=25
EOF
	
	echo "+ Configuring Client"
	cat << EOF | sudo socat - UNIX-CONNECT:"$UAPI_SOCKET_CLIENT"
set=1
private_key=$PRIVATE_KEY_HEX_CLIENT
listen_port=51820
EOF
	
	# Peer config (with set=1)
	cat << EOF | sudo socat - UNIX-CONNECT:"$UAPI_SOCKET_CLIENT"
set=1
public_key=$PEER_PUBLIC_KEY_HEX_CLIENT
allowed_ip=$WG_SERVER_IP
endpoint=10.0.0.1:51820
persistent_keepalive_interval=25
EOF

	

}

function configure_wireguard_wg() {
	echo "+ Configuring WireGuard peers with wg"
	
	sudo ip netns exec $SERVER wg set $WG_SERVER \
		private-key $SERVER_PRIV_KEY

	sudo ip netns exec $CLIENT wg set $WG_CLIENT \
		private-key $CLIENT_PRIV_KEY
		
		
	sudo ip netns exec $SERVER ip link set $WG_SERVER up
	sudo ip netns exec $SERVER ip addr
	
	sudo ip netns exec $CLIENT ip link set $WG_CLIENT up
	sudo ip netns exec $CLIENT ip addr
	
	sudo ip netns exec $SERVER wg set $WG_SERVER \
		peer $(< $CLIENT_PUB_KEY) \
		allowed-ips 10.10.10.2/32 \
		endpoint 10.0.0.2:51820 \
		#listen-port 51820

	sudo ip netns exec $CLIENT wg set $WG_CLIENT \
		peer $(< $SERVER_PUB_KEY) \
		allowed-ips 10.10.10.1/32 \
		endpoint $SERVER_ENDPOINT \
		#listen-port 51820
}

function up() {
	
	WIREGUARD_LOG_LEVEL_ENV="${2:-silent}"

	if [[ ! -f "$WIREGUARD_GO" ]]; then
	echo "- wireguard-go binary not found from current directory!"
		exit 1
	fi

	echo "+ Killing leftover wireguard-go processes..."
	sudo pkill wireguard-go || true
	sudo ip netns exec $SERVER pkill wireguard-go || true
	sudo ip netns exec $CLIENT pkill wireguard-go || true

	generate_keys
	setup_tun
	start_wireguard_go
	configure_interfaces
	configure_wireguard

	echo "+ Tunnel setup complete."
	echo "+ Test with: sudo ip netns exec $CLIENT ping -nc 3 ${WG_SERVER_IP%/*}"

}

function down() {
	echo "+ Cleaning up WireGuard interfaces (note: wireguard-go processes will still run)"

	sudo ip netns exec $SERVER ip link del $WG_SERVER 2>/dev/null || true
	sudo ip netns exec $CLIENT ip link del $WG_CLIENT 2>/dev/null || true

	echo "+ Killing wireguard-go processes..."
	sudo ip netns exec $SERVER pkill wireguard-go || true
	sudo ip netns exec $CLIENT pkill wireguard-go || true
	sleep 1  # let them terminate cleanly

	echo "+ Removing key files"
	rm -f $SERVER_PRIV_KEY $SERVER_PUB_KEY $CLIENT_PRIV_KEY $CLIENT_PUB_KEY
}

# By default, TUN is not available inside network namespaces. You must mount it into the namespace.
function setup_tun() {
    for ns in $SERVER $CLIENT; do
        ns_pid=$(sudo ip netns pids $ns | head -n1)
        ns_path="/var/run/netns/$ns"

        # Recreate the symlink only if missing or broken
        if [[ ! -e "$ns_path" ]]; then
            sudo mkdir -p /var/run/netns
            sudo ln -s /proc/$ns_pid/ns/net $ns_path
        fi

        # Ensure /dev/net/tun exists in the namespace
        sudo ip netns exec $ns bash -c '
            mkdir -p /dev/net
            [[ -c /dev/net/tun ]] || mknod /dev/net/tun c 10 200
            chmod 600 /dev/net/tun
        '
    done
}

case "$1" in
	up)
		up "$@"
		;;
	down)
		down
		;;
	*)
	echo "Usage: $0 {up [loglevel]|down}"
		exit 1
		;;
esac
