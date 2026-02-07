# Translation

Ein normales IP-Paket geht an eine SCION-mapped IPv6-Adresse (fc00::/8). WireGuard soll das über den Tunnel transportieren.

## Datenfluss (Client-Seite):

1. App schickt ein IP-Paket (IPv6/UDP oder IPv6/TCP) an fc00:... (SCION-mapped Ziel).

2. Das Paket wird vom Kernel über wg-client geroutet und landet in wireguard-go im RoutineReadFromTUN().

3. Translator erkennt: dst ist SCION-mapped → Translation.

4. Translation baut ein “SCION packet” (SCION Header + inner L4 + Payload).

5. Danach noch eine Outer IP/UDP Kapsel drum herum: [outer IPv6][outer UDP][SCION bytes]

6. Schreiben des neuen “Outer IP-Paket” zurück in elem.packet und WireGuard ganz normal encrypten & senden lassen (Peer lookup, stage, send).

7. Auf der Gegenseite (Server-WG) wird WireGuard entschlüsseln → das Outer IP/UDP-Paket kommt wieder aus dem TUN.

8. Dort muss es dann als SCION-underlay erkannt werden, UDP payload (SCION bytes) raus, und als SCION weiter verarbeitet/geroutet werden.


# Translator bekommt localIA (ISD-AS) aus config?
JA okay also muss der sender für den SrcIA wer sein? Also eigentlich bin ich es ja. Aber ich habe ja nicht unbedingt eine ip die zu scion gemapped werden kann.

Okay LocalIA wird in main aus as Enviornment variables gelesen erstmal.
Und dann an den Translator übergeben.


## Probleme

### Ein “zweites IP/UDP Paket” erzeugen und so tun, als wäre es normaler Traffic
Trennung zwischen normalen IPv6 Paketen und Scion-underlay IPv6/UDP Paketen.
Sonst passiert auf der Receiver-Seite z.B.:
AllowedIPs lookup findet keinen Peer
droppen das Paket oder routen falsch
oder versuchen es nochmal zu übersetzen (“Translation loop”) - Eigentlich leicht trennbar durch send.go und receive.go

### Auf der Empfangsseite kommt aus dem TUN wieder “ein IPv6 UDP Paket” raus.
Brauchen dort logik für:
Wenn UDP dport == SCION_UNDERLAY_PORT → das ist SCION
sonst normales IP handling


## Alternativer Ansatz: UDP-Socket-Ansatz:

IPv6/UDP(dstPort = SCION_UNDERLAY_PORT) + SCION bytes


Translator baut nur SCION bytes, und sendet sie per UDP socket an nextHop.
Der Kernel routet diese UDP Pakete über wg-client, also kapselt WireGuard automatisch.

kein Outer IP/UDP Byte-Paket mehr bauen
Sparen uns die komplette Outer IPv6/UDP Serialize-Logik. Weniger Bugs.

Peer im richtigen AS, ist ein Argument für den einfachen Buffer-Ansatz, weil:

brauchen nur einen klaren “Transport-Kanal” durch WG

und auf der Receiver-Seite eine feste Stelle, wo wir SCION “einspeisen”.