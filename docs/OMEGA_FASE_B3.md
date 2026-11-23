# OMEGA Fase B3 — Precisión y cobertura (lote YT Music)

Alcance: 13 mejoras salidas del informe real de YouTube Music (81 MB, 6 dex)
con el APK B2. Sin reescribir nada; cada una con tests.

## Precisión

- Cadenas por clave completa: `LogicNet.chainsTo` ya no casa por nombre
  pelado (`<init>` casaba con todos los constructores) sino por clave
  `Lclase;->metodo`. `sensitiveTargets` devuelve claves completas.
- Ofuscación R8: `isShortName` también marca minúsculas de 3-5 letras
  (`aftz`), no solo ≤2. Antes: ratio 0.01 en app visiblemente ofuscada.
- IPs: se excluyen OIDs X.509 (arcos 1.2/1.3/2.5 y secuencias punteadas
  largas como 1.3.6.1.4…). Una IP real en esos arcos se pierde (asumido).
- Emails: se excluyen assets iOS (`logo@2x.png`, `@1x/@3x`).
- `llama=` sin duplicados (`addSuspCall`; antes ×5 la misma línea).
- Secretos por palabra: se excluyen descriptores de clase (`L…$Token;`).

## Cobertura

- Herencia: `suspiciousLabelWithSupers` sube por superclases (tope 8,
  anti-ciclos) con el mapa `clase→super` que entrega `DexCalls`
  (best-effort: solo clases definidas en el dex). Un
  `addJavascriptInterface` sobre subclase de WebView ya casa.
- Segunda pasada dex completo: `collectOwnCalls` añade al grafo las aristas
  sensibles invocadas desde librerías (adrt…) y sus cadenas a StringRefs.
  `suspCalls` sigue propio (su sección lo afirma); el grafo es más amplio.
  Nota por dex `librerías X: muestra parcial (topes)` si recorta.
- Entradas verificadas: `ManifestChecks.components` + `resolveDescriptor`
  (relativos con paquete) → `manifestClasses`; la línea de entrada lleva
  ` [manifest]` si su clase está declarada.
- Origen por URL: `urlOrigin` (dex/arsc, primero que la ve); línea con
  ` [arsc]` si no atribuida y solo-ARSC (explica el porqué).

## Presentación y exportación

- Colas agrupadas: `LogicNet.groupByTrunk` + `cadena=… xN` y `desde=…`
  (tope 5 + resto). Los hallazgos `cadena` siguen atómicos (uno por cadena).
- `toJson`: `graphNodes/Edges/Truncated`, `stringValues/Pairs/Truncated`,
  `redEntries`, `redChains`, `redTruncated`. `summarizeRed` compartido
  con toText (sin duplicar el cómputo).
- Deeplinks sin duplicados en `ManifestChecks`.

## Pruebas

Suite local 109/109 (94 + 15): DexCallsTest +2 (supers, fixture
propia+librería), DexParserTest +2 (nuevo: ofuscación, resolución),
ManifestChecksTest +2, ReaEngineTest +3 (dedup, scan, json, librería…),
RefGraphTest +1 (resuelta), LogicNetTest +4 (clave exacta, agrupado,
verificada). `JadxAdapterTest` incluido con slf4j.
