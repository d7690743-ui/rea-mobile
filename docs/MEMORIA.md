# Memoria — optimización para APKs grandes

Problema: con APKs grandes el análisis no terminaba por falta de memoria.

## Dónde estaba el pico

Por cada DEX, el análisis decodificaba la tabla de strings COMPLETA
cuatro veces seguidas y solapadas (DexParser, DexCalls ×2 pasadas,
FlowScan), más otra vez en extracción (SmaliDumper) y el pool ARSC
entero. Con 100k–2M strings por dex, cada tabla son decenas de MB
retenidos a la vez que los bytes del dex y los acumuladores.

## Qué se cambió (sin cambiar resultados)

- `engine/DexStrings` + `engine/DexTypes` (nuevos): pools perezosos con
  caché LRU acotada (4096/1024). Misma semántica ("?"/"" en los mismos
  casos) sin arrays completos. Los usan DexParser, DexCalls, FlowScan y
  SmaliDumper.
- `DexParser`: proto solo para la muestra (antes: para cada método).
- `DexCalls`: un solo recorrido (`includeLib`); aristas/strings ajenos en
  `libEdges`/`libStrings`; `codeOffs` + `table` para FlowScan. Cobertura
  propia idéntica; presupuestos independientes por lado.
- `FlowScan.buildFrom`: construye IRs sobre lo ya recorrido (sin
  re-recorrer ni re-decodificar). `collect()` se conserva para tests.
- `AxmlDecoder.parseStringPoolHead` + `ArscStrings`: conteo + cabecera
  (10k) sin retener el pool entero.
- `SmaliDumper.StreamDump`: volcado incremental; `dumpAll` conserva su
  semántica sobre él.
- `ReaEngine.extractToZip`: streaming por dex (antes retenía TODOS los
  dex); suelta smali/strings ya volcados antes de JADX.

## Medición (JVM, YouTube Music 81MB + dex sintético 600k strings)

| Caso | Antes | Después |
|---|---|---|
| analyze YTM, informe TXT/JSON | — | TXT idéntico; JSON solo +18 `stringValues` (muestreo bajo truncamiento declarado) |
| dex 600k strings @128m | 2161 ms, pico 113MB | 846 ms, pico 82MB |
| dex 600k strings @64m/@48m | OOM | completa |
| analyze YTM @32m | completa | completa (sin regresión) |
| extract YTM @128m | pico 118MB | pico 104MB |

Tests: `DexStringsTest` (3), `DexCallsTest.paseFusionadoEquivale`,
`FlowScanTest.buildFromEquivaleACollect`, `SmaliExtractTest.streamDumpEquivale`;
suite completa en verde salvo los 8 pre-existentes de `JadxAdapterTest`
(necesitan la librería JADX real, igual que en el árbol intacto).
