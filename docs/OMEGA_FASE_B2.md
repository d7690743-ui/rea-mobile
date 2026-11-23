# OMEGA Fase B2 — Red lógica (LogicNet) + StringRefs

Alcance: razonar sobre el grafo (Fase B) sin reescribir nada + atribuir
cadenas a métodos (#2). Roles por clase y data-flow, pendientes.

## Diseño

- `engine/LogicNet`: consultas sobre `RefGraph` (utilidad estática, sin
  estado). No analiza DEX ni infiere llamadas: entradas por nombre
  (`ENTRY_METHODS`), `reachableFrom` (BFS con topes), `chainsTo` (DFS
  inverso entrada→API sensible por clave completa, solo cadenas completas;
  en B2 casaba por nombre y se corrigió en B3), `topCallees`
  (fan-in, espejo de `topCallers`).
- `engine/StringRefs`: índice cadena→métodos, espejo de `RefGraph`.
  `usersOf` (exacto) + `usersOfContaining` (subcadena, para URLs dentro de
  literales mayores). Tope `MAX_PAIRS=20000`, cuenta descartes.
- Extensión mínima de `DexCalls` (aditiva): `StringRef{user,value,dex,pos}`
  + `Result.strings` en la misma pasada (rama `R_STR`; jumbo lee u32).
  `Result.stringsTruncated` separado. `DexCallsTest` intacto.
- Vive en `engine` (no en `intelligence`) para no crear ciclo
  engine↔intelligence: el razonamiento que produce hallazgos está en
  `ReaEngine.feedIntelRed`, como `feedIntelGraph`.

## Integración

- `ReaEngine.ApkReport.stringRefs`: se alimenta por dex en `collectOwnCalls`.
- Informe: `url=... <= llamador` en INDICIOS (hasta 2 + resto; sin
  atribución la línea queda igual); sección `=== RED (entradas=E cadenas=C)
  ===` con entradas+alcance, cadenas `a -> b -> c` y hubs.
  `[recortado]`/`[+]` marcan topes.
- Registro OMEGA: `feedIntelRed` crea hallazgos `cadena` por cadena completa
  (tope 20), confianza MEDIA, tipo STATIC y limitación obligatoria
  "ejecución no observada". Categoría propia (no `red`: esa es de URLs).

## Pruebas

`StringRefsTest` (7): exacto/contenido, duplicados+topes, dex const-string,
dex jumbo, dex sin strings intacto, informe atribuye, malas.
`LogicNetTest` (7): entradas, alcanzable+topes, cadenas, múltiples+
profundidad, topCallees, informe+registro, malas.
Suite local 94/94 (80 + 14 nuevas); `JadxAdapterTest` incluido con slf4j.

## Validación en teléfono (caso real)

Abrir YouTube Blocker: INDICIOS debe mostrar `url=https://www.youtube.com/`
con `<=` y su método; RED debe listar entradas (`onCreate`, `onClick`…),
alcances y hubs. Cadenas a API sensible: previsiblemente
`(sin cadenas a API sensible)`, porque el único candidato
(`addJavascriptInterface`) se invoca sobre la subclase
`BackgroundMediaWebView` y el patrón solo casa `WebView` exacto
(limitación de herencia conocida; resuelta en B3 por superclases).
