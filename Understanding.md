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

