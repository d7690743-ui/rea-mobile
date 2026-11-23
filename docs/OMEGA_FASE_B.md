# OMEGA Fase B — RefGraph (índice de llamadas)

Solo RefGraph. StringRefs y demás módulos, pendientes.

## Diseño

- `engine/RefGraph`: índice en memoria sobre `DexCalls.Result`. No analiza
  DEX ni infiere nada: cada arista viene de un `invoke` real.
- Clave de método: formato DexCalls `Lcom/x/A;->foo` (sin proto).
- `RefEdge` conserva caller, callee, clase/método del llamador y del llamado
  (descriptores completos `L...;`), DEX de origen y posición (offset en units).
- API: `callersOf`, `calleesOf`, `edgesFrom(clase, metodo)`,
  `containsMethod`, más `topCallers(n)` para diagnóstico y `edges()`.
- Deduplicación por (caller, callee, dex, pos): el mismo sitio colapsa;
  dos sitios distintos se conservan.
- Tope `MAX_EDGES=20000`, cuenta descartes, marca `truncated()`.
- Extensión mínima de `DexCalls` (aditiva): `Edge.dex/pos` + overload
  `collect(dex, pkgSlash, dexName)`. `DexCallsTest` intacto.

## Integración

- `ReaEngine.ApkReport.graph`: se alimenta por dex en `collectOwnCalls`.
- Informe: sección `=== GRAFO (nodos=N aristas=M) ===` con la diagnóstica
  `exec<=llamador` (¿quién llama a `Runtime.exec`?) y top 5 llamadores con
  ejemplos de llamados (responde "¿qué llama X?" en genérico).
- Registro OMEGA: `feedIntelGraph` crea hallazgos `grafo` por llamada a API
  sensible (tope 100), confianza MEDIA, tipo STATIC y limitación obligatoria
  "ejecución no observada". Nunca HIGH: referencia ≠ ejecución.

## Pruebas

`RefGraphTest` (10): interna, externa, múltiples callers, sin llamadas,
desconocidos/nulos, duplicados, truncado, topCallers, dex real exec
(`DexCallsTest.buildInvokeDex`), dex real multi-caller (`buildTestDex`
iv/ip/q5→foo), sección de informe + registro, end-to-end `analyze()` sobre
mini-APK con exec.

## Validación en teléfono (caso real, 2026-11-22)

Abierto YouTube Blocker con el APK faseb (`ccaa5cf0`):
`exec<=(nadie detectado)`. Correcto: ningún método propio invoca `exec`
(el Java decompilado lo corrobora); la referencia en `method_ids` viene de
las 2 clases `adrt`, fuera del alcance de código propio.
Referencia ≠ ejecución confirmada.
