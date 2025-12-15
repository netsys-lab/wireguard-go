## Wie werden IP Pakete erstellt

## Wie werden die IP Pakete an das Interface geleitet

## Wie werden die IP Pakete vom Interface verarbeitet

Liest Batch-weise aus dem TUN
Schreibt die Nutzbytes ab bufs[i][offset:] und die Länge in sizes[i]
offset lässt Headroom für spätere WireGuard-Header

pkt ist ein Slice in dieselbe Backing-Array wie elems[i].buffer
elem.packet zeigt also immer auf einen Ausschnitt von elem.buffer
Änderungen an elem.packet wirken in-place im Buffer

## Wie verarbeiten wir die Bytes weiter

In ReadfromTUN wird ein window über die für das Paket validen bytes erstellt.
Diese Validen bytes speichern wir uns ab.

Nachdem ermittelt wird ob es sich um ein IPv4 oder v6 Paket handelt übergeben wir die bytes an unsere Funktion.

In unserer Funktion wird das pkt in-place manipuliert, da es eine slice des elem.buffer arrays ist.

### Wie sind IPv4 und IPv6 Pakete aufgebaut


### Wir verwenden gopacket (layers)



## ToDo:

Steht der PathCache? Ansonsten versuche ich ohne ihn mit einer Callback und dem Interface einen Testcase zu bauen und Fide kümmert sich um PathCache

Test Cases for Translation - Unit Tests für Translation - orientieren an Lars C++, Go Listen? Testify. Packet generation. Wie PathCache mocken. Callback

Test Cases für PatchCache und PathCache

Deamon initialisieren - Connection to Deamon bei Device initialisierung. Und eigenes AS abfragen

Eigene / Host adresse abfragen - diese muss auf eine Ipv6 abgebildet werden. - Das ist die IP source adresse im Scion Header
Aus Host Mapped IPv6 adresse muss dem Interface zugeordnet werden. - damit Kernel auch ipv6 adresse als source verwenden können. (muss keine fc00 adresse sein)
ip -6 route fc00: dev, scion proto
Dies kann statisch über ein shell skript passieren
Überprüfen wo und wie dies in Wireguard programatisch gelöst werden kann. Interface zu Ip. Orientieren an scintra tun setup .cpp.

Was sind Flows?
Map die Flows enthält, HashMap:Flow id, Flows. FlowId aus paket, 

PAN - Fidelio hat das gesehen, als callback function die Path Policy.

Paket Parsen? Was, wann und warum? (Receive und Prase vor TranslateEgress)

Path Selection Dummy Function -> Die soll Path Cache Path Cache abrufen und später dann den richtigen Pfad auswählen.

PathCache with snet path objects - integrate into Translation

Expand to (3) Namespaces (host0, host1, root namespace) - run scion topology in Root namespace

Skript to send IPv6 Packets

Test Cases für Translation: Scion Packet with Path etc. 

Dokumentation: TestEnv Setup + Description, Debugger, TestEnv Packet Sending + Scapy Sniff, PathCache, Translation, 

--- PathCache Update using Deamon etc?

--- PathCache Update using Paths TTL (Expiry time)