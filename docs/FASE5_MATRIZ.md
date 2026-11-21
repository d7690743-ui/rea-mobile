# Fase 5 — Matriz de pruebas + comparativa JADX

Corpus: APK propio `tubemusic` (multidex: 5 dex, Kotlin+Java) + DEX
sintético (`SmaliExtractTest.buildTestDex`, 5 métodos). Medido en local
salvo indicación. Nada aquí se declara sin su prueba o medición.

## Matriz por característica

| Característica | Smali propio | JADX adapter | Motor propio | Evidencia |
|---|---|---|---|---|
| Java clases propias | 124 clases OK | 125 java, 0 err, 16 s | visor Smali/Java | `DumpAllProbe`, `JProbe` |
| Kotlin (lambdas, `$` sintéticos) | etiquetas OK | 0 errores | pendiente F3.4 | `MainActivity$$ExternalSyntheticLambda*` |
| Multidex (5 dex) | `dumpAll` todos | nativo (4462 clases) | por método (F3.1) | `unzip -l`, `JProbe` |
| Clases internas (`R$*`, `$show$1`) | OK | `getClassesWithInners` OK | — (hereda smali) | volcado `/tmp/smali-fixed` |
| packed-switch | 2/2 exactos vs baksmali | OK | cases en CFG (synth) | size+first_key+claves bit a bit |
| sparse-switch | 3/3 exactos vs baksmali | OK | cases en CFG (synth) | MainActivity 3, MusicDownload 7, PlaybackService 6 |
| fill-array-data | 0 = 0 vs baksmali | OK | payload detectado | sin falsos positivos |
| if/goto | etiquetas `:L0004` OK | OK | 3 bloques exactos (synth) | `IrBuilderTest.bloquesIfGotoExactos` |
| Bucles | etiquetas OK | OK | pendiente F3.4 | — |
| try/catch | omitido (documentado) | OK con WARNs multi-try | pendiente F3.4 | WARN jadx "bottom block", 0 errores |
| Ofuscación | ratio en `analyze` | best-effort | pendiente | heurística, no desofusca |
| APK grande / OOM | topes + `largeHeap` | completo + fallback por dex | topes `MAX_INSNS` | v0.3.2, `apkReintentaPorDexTrasAbortoMemoria` |

## Comparativa contra referencia

- Smali vs baksmali (dexlib2, verdad de bytes): coincidencia por fichero
  en switches (3 ficheros, 5 payloads) y claves idénticas bit a bit;
  direcciones de dispatch iguales (p. ej. payload `0x44`).
- Targets switch relativos al dispatch (no al payload): derivado de
  `dispatch@0x19 + raw = :sswitch_37/:sswitch_2a/:sswitch_1d` de baksmali.
- JADX adapter (jadx-core 1.5.2 API) vs CLI desktop 1.5.7: misma familia;
  medición local con 1.5.7: 4462 clases, 125 propias, 0 errores, 16 s,
  sin recorte (tope 300 no alcanzado).
- Comparación Java salida-vs-salida automatizada: no se hace (el plan
  F3.5 la define manual); la paridad que se automatiza es a nivel dex
  (payloads) y sintético (bloques).

## Pendiente (no prometido)

- F3.2 tipos, F3.3 SSA-lite, F3.4 estructuración, F3.5 emisor.
- Validación en dispositivo del descompilado Java v0.3.2 (usuario).

Nota v0.3.2: APK intenta carga completa (125 java, 0 err) y si aborta
por memoria reintenta por dex (medido: 124 java, 8 err métodos cross-dex).
Se devuelve el mejor parcial; el visor muestra fases ("cargando APK",
"dex i/N", "reintentando por dex").
