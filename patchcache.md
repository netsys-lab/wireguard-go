## Patch Cache

package patchcache

### Deamon

Scion Deamon returns multiple fields:

|  Fields |  Description |  
|---|---|
|  Raw | The raw SCION path bytes  | 
|  Interfaces | Sequence of (ISD-AS, InterfaceID) hops.
|  Path MTU |   Path MTU (maximum transmission unit).
|  ExpTime |   Path expiration time.
|  Fingerprint |  Unique identifier for the path.
|  Metadata |   Additional info

### Cache

#### Route / Key

We have the Route as key.
A combination of source and destionation addr.IA.
In SCION they are uint64 under the hood, which means they comparable and can be used for the map.

    type Route struct {
        Src addr.IA
        Dst addr.IA
    }

#### Cache Struct

A Map of the Paths for a given Route.

The Cache should store, the Raw Bytes, Interfaces and ExpTime

    type Cache struct {
        mu    sync.RWMutex
        store map[Route][][]byte
        //or
        //store map[Route][]snet.Path
    }

### Functions

#### New

    func New() *Cache {
        return &Cache{
            store: make(map[Route][][]byte),
        }
    }

#### Lookup

Lookup should return the Paths for a given Source and Destionation combination.

The translate function needs the selected Path in Byte format.

    func (c *Cache) Lookup(src, dst snet.UDPAddr) ([]byte, bool) {
        key := Route{Src: src.IA, Dst: dst.IA}
        c.mu.RLock()
        defer c.mu.RUnlock() // what is this defer for?
        paths, ok := c.store[key]
        if !ok || len(paths) == 0 {
            return nil, false
        }
        //Return a Copy
        out := make([]byte, len(paths[0]))
        copy(out, paths[0])
        return out, true
    }

#### Store

This Function stores for a source and destination addr.IA pair, the Raw Path bytes, Interfaces and ExpirationTime

    func (c *Cache) Store(src, dst addr.IA, pathBytesList [][]byte) {
        c.mu.Lock()
        defer c.mu.Unlock()
        k := key(src, dst)
        // defensive deep copy
        cp := make([][]byte, len(pathBytesList))
        for i := range pathBytesList {
            if pathBytesList[i] == nil {
                continue
            }
            b := make([]byte, len(pathBytesList[i]))
            copy(b, pathBytesList[i])
            cp[i] = b
        }
        c.store[k] = cp
    }


#### Remove


## Notes

- Path Selektion erstmal als erster. Pfade vom Deamon sind nach Hop länge sortiert, also erster hat wenigste Hops. - Reicht für ersten Schritt.
Path Selection Dummy Funktion nicht vergessen

- Path Updates Asynchron - Go Routinen / Subroutine - Um Deadlock/Locking zu verhindern.

- Regular Time Based Async refresh of Paths - Store Paths - Co Routine? In JPAN Path Pool - RefreshIntervall

- Alle Pfade zusammen refreshend sobald einer abläuft, das ablaufdatum von dem ältesten Pfad nehmen.

- Neue Pfade wenn keiner für dst src vorhanden oder wenn abgelaufen (wenn refresh Timer - minimum path lebensdauer) (Savety Margin das Pfade vor Ablauf abgerufen werden.)
