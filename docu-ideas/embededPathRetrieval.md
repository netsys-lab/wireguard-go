## embeded Path Retrieval

- New Signature for NewDevice in device.go:
    main.go übergibt configdir für Retriever (Deamon)

- Catchen von err bei Retriever erstellung

- ConfigDir zur laufzeit bekommen:

    - Hardcoden:
        ```
        export SCION_CONFIG_DIR=/home/fidelioluc/scion/gen/ASff00_0_110
        ./wireguard-go wg0
        ```
        Oder Inline:
        ```
        SCION_CONFIG_DIR=/home/fidelioluc/scion/gen/ASff00_0_110 ./wireguard-go wg0
        ```

    - UAPI-Erweiterung:

- Bootstrap Server in anderem Namespace starten
    TODO: Merge mit TestEnv

- Konkreter Bootstrap-Fetcher in Go

### UAPI-Erweiterung:

UAPI = “Userspace API” von WireGuard.
WireGuard (auch wireguard-go) hat neben dem Network-Interface (wg0) noch einen Control-Channel, über den man Konfiguration setzt und ausliest (Keys, Peers, AllowedIPs, ListenPort, …)
Die Nachrichten sind simpel: Textzeilen key=value.

Beispiel (vereinfacht):
```
set=1
private_key=...
listen_port=51820
public_key=...
allowed_ip=10.0.0.0/24
...
```

#### Warum macht UAPI dein Leben einfacher?

Weil damit SCION-spezifische Konfig genauso “wie WireGuard-Konfig” gesetzt werden kann.

Android-App muss sowieso “WireGuard konfigurieren”,
kann dann im selben UAPI-Call zusätzlich senden

UAPI ist der Standard-Konfigkanal von WireGuard.

## Bootstrap

```
GET ${baseURL}/topology → schreibt ${configDir}/topology.json
```
```
GET ${baseURL}/trcs → Liste der TRCs
```
Für jede TRC-ID:
```
GET ${baseURL}/trcs/isdX-bY-sZ/blob → schreibt ${configDir}/certs/ISD{X}-B{Y}-S{Z}.trc
```


## Einbauen in Test

Bsp:
sudo ip netns exec Server python3 bootstrap-server.py /home/fidelioluc/scion/gen/ASff00_0_110 10.0.0.1 8042

export SCION_BOOTSTRAP_URL=http://10.0.0.1:8042
# optional: wenn du NICHT willst dass er /tmp nutzt:
export SCION_CONFIG_DIR=/tmp/client-scion-config

### Einbauen in shell skripte so:
```
sudo ip netns exec $CLIENT bash -c "
  export WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1
  export LOG_LEVEL=$WIREGUARD_LOG_LEVEL_ENV
  export SCION_BOOTSTRAP_URL=http://10.0.0.1:8042
  $WIREGUARD_GO --foreground $WG_CLIENT > /tmp/wg-client.log 2>&1
" &
```

## Testen:

1. make laufen lassen -> wireguard-go bauen

2. namespace-tunnel.sh ausführen
    ```
    /namespace-tunnel.sh up
    sudo ip netns exec Client ping -c 1 10.0.0.1
    ```

3. Scion asuführen (Topo)
    ```
    In Server NS
    scion.sh topology -c tiny.topo
    scion.sh run
    ```
    scion setup script, AS addressen anpassen?

4. Bootstrap Server starten
    ```
    sudo ip netns exec Server python3 ./bootstrap-server.py "$SCION_DIR/gen/ASff00_0_111" 10.0.0.1 8042
    sudo ip netns exec Client curl -s http://10.0.0.1:8042/topology | head
    sudo ip netns exec Client curl -s http://10.0.0.1:8042/trcs | head

    ```

5. Wireguard-go starten


Komplettes skript: bootstrap_test.sh

```
./bootstrap_test.sh
```




# Notes:

Bootstrap Server auch über Tunnel erreichbar.

Bootstrap nach lokalen ASN fragen

Tunnel nur wenn Bootstrap erreichbar
WG nur wenn Tunnel + Bootstrap erreichbar


Wie die WG App funktioniert, wann routen festgelegt.

Apparently: Android VpnService-API

SCION / SCITRA APP Name

Plus Button.
Datei oder Archiv
QR Code
Oder Manuell eingeben

Ersetzen:
Bootstrap von Liste wählen - Fetch / Sync von Server

Bootstrap Manuell
QR Code für Bootstrap server + WG Config


Von Bootstrap bekommen wir topology & trcs

Brauchen - IP + Public key von WG Peer + Conf für unsere Client

SSO

QR Code  -> .conf

Connect - Tunnel erstellen


Annahme: QR existiert: Bestehend aus standard WG QR code + Bootstrap adr.

[Interface]
    Address = 10.192.122.1/24
    Address = 10.10.0.1/16
    SaveConfig = true
    PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
    ListenPort = 51820

    [Peer]
    PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
    AllowedIPs = 10.192.122.3/32, 10.192.124.1/24

    [Peer]
    PublicKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=
    AllowedIPs = 10.192.122.4/32, 192.168.0.0/16

    [Peer]
    PublicKey = gN65BkIKy1eCE9pP1wdc8ROUtkHLF2PfAqYdyYBz6EA=
    AllowedIPs = 10.10.10.230/32

[SCION]

    bootstrap=https://...


Lokar DNS Server oder konf enthällt DNS Adrs

Tunnel - Route Tunnel DNS Bootstrap
DNS Server setzten
Bootstrapping mit URL
Scion Daemon init + AS Info (local AS = 0 ) grpc call
TTTTrannnnnnnnnnnnnnnnnnnnnnnnnnnnnslation#


App Speicherfunktion von Tunneln - schon in App
Muullllllllltln tunnel allowed? Nicht für SCION

