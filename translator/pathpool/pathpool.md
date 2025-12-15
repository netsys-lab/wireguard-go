# Path Pool

Inspired from anapaya path pool, simple logic, no path selection mechanisms.

## Test Cases

- Manual add and get `TestPathPoolAddAndGet`
- Add and get multiple paths `TestPathPoolMultiplePaths`
- Expired Path not retrieved `TestPathPoolExpiredPaths`
- If no path found retrieve new path `TestPathPoolReadThrough`

## Future Test Cases

- Fingerprint, gleicher pfad, gleicher fingerprint. Anderer Pfad anderer Print
- Mehr Assertions, nicht nur Länge
- Updaten von vorhandenem Pfad wenn mehrmals gleicher geaddet?
- Concurrency / Race? Retriever nur einmal aufrufen Go routinen?
