# PHANTOM — Paquete de conocimiento reconstructivo

Motor que convierte el inventario forense en conocimiento agrupado por
función para que una IA reimplemente (ver `docs/RECONSTRUCCION.md`).
Trabaja EN CONJUNTO con OMEGA y ALFA: consume sus salidas del ApkReport
(grafo, strings, flujo, taint, ELF/JNI, UI, Blueprint) sin re-parsear el
APK. Perezoso con caché (una sola vez por informe). Java puro, topes
anti-OOM, nunca lanza.

```
OMEGA (RefGraph, StringRefs, FlowScan, Taint, SearchPlan…)
ALFA  (AlfaElf/Jni/Ui/Corr…)
        │  salidas ya en ApkReport
        ▼
Phantom.summarize(r) → PhantomResult (caché en ApkReport.phantom())
        ├─ PhantomGroup     FN-## entry→subgrafo→red→permisos→pantallas
        ├─ PhantomMetric    completitud campos OK/8 + distribución
        ├─ PhantomNet       contratos endpoint+verbo+payload+permiso
        ├─ PhantomUi        setContentView resuelto + handlers + Compose
        ├─ PhantomStore     SQLite/prefs/SQL por evidencia
        ├─ PhantomData      parcelables/json-lib/modelos/JSON lits
        ├─ PhantomJni       RegisterNatives best-effort + unión
        ├─ PhantomTaint     multisalto (2 extra) + reflexión resuelta
        └─ PhantomDecompile prioridad JADX (entradas+pantallas+grupos)
        ▼
sección PHANTOM + bloque "phantom" en toJson + rea/paquete.json (R1)
+ PAQUETE JSON en FullReport + 30 hallazgos intel (10+5+5+5+5)
```

## Las 9 piezas (qué se incorporó)

1. R1 paquete.json: `extractToZip` emite `rea/paquete.json` (= toJson con
   bloque phantom); `FullReport.Extras.packageJson` + sección; el visor lo
   genera con un solo `analyze()`.
2. Agrupador FN-##: entradas ALFA ordenadas (lifecycle > normales >
   sintéticos), BFS profundidad 3, muestra retenida (no subgrafos).
3. Métrica: OK/PARCIAL/FALTA por campo y distribución ("60: 0 ≥6/8…").
4. Contratos de red: verbo/content-type/pistas desde literales de los
   mismos métodos usuario; permiso estilo ALFA-3.
5. Pantallas: llamadores de setContentView (id por IR+grafo cuando hay
   evidencia; si no, `(layout?)` = PARCIAL honesto) + Compose por aristas.
6. Almacenamiento/datos: SQLiteOpenHelper por herencia, SQL/prefs/JSON
   por literales, parcelables y json-lib por grafo.
7. JNI dinámico: `ElfInfo.jniDynamic` (≤40 pares nombre|firma) rastreado
   en head/tail ya cargados cuando hay JNI_OnLoad; unión por nombre.
8. Taint-X: encadena 2 saltos extra hacia sumideros sobre la base OMEGA
   (reutilizada, no recomputada) + forName/getMethod/loadClass por consts.
9. Java dirigido: overload `decompileFiltered(..., prioritySmali)` que
   ordena (prioritarias primero, mismas referencias); el visor calcula la
   prioridad con un `analyze()` previo y gc (fallback: orden de carga).

## Cambios en código existente (aditivos)

- `ReaEngine`: `phantom()` + `flow()` memoizados; sección PHANTOM;
  bloque phantom en JSON; scan JNI en el loop .so (3 líneas + guardias);
  `rea/paquete.json` en el ZIP; `feedIntelPhantom`; 2 limitations
  actualizadas. `summarizeFlow` memoiza (mismo resultado, 1 cómputo):
  el informe YTM pasa de ~31 s a ~13 s.
- `StringRefs`: `literalsOf` + `scanContains` + `usersOfContaining(sub,cap)`
  (el original intacto).
- `AlfaElf.ElfInfo`: campo `jniDynamic` (vacío por defecto).
- `JadxAdapter`: overloads con prioridad (los existentes delegan).
- `FullReport`: `Extras.packageJson` + sección + flag.
- `CodeViewerActivity`: prioridad dirigida + paquete JSON (1 analyze).

## Memoria y regresión (YouTube Music 81 MB, JVM)

| Caso | Base | PHANTOM |
|---|---|---|
| analyze 128m | 15,2 s | 12,5 s |
| toText+toJson 128m | 16,3 s | 0,3 s |
| pico heap 128m | 149 MB | 144 MB |
| 64m / 48m | OK | OK |
| 32m | OOM parcial (capturado) | idéntico (paridad, sin lanzar) |

Regresión: 17 secciones TXT idénticas byte a byte salvo 2 líneas de
LIMITACIONES (actualizadas a conciencia) y el conteo INTELIGENCIA
147→161 (14 hallazgos PHANTOM nuevos; los 147 intactos). JSON válido.

## Límites honestos

- Layout id→nombre sin resolver (sin mapa ARSC retenido): `(layout?)`.
- Métrica YTM ofuscado: 60 funciones ≤3/8 (tope 60 alcanzado; el informe
  ahora lo MIDE en vez de estimarlo).
- Extracción ZIP (`extractToZip`) sigue con JADX sin prioridad (el visor
  sí la usa): evita retener el report durante JADX.
- Reflexión/multisalto best-effort; modelos por nombre LOW.

## P2 (incremento sobre informe YTM 4)

Del análisis del primer informe PHANTOM real salieron 6 causas:

- P2.1 matching por clase + cierre exacto: el grupo cruza store/datos/
  nativo contra su subgrafo depth-5 completo (transitorio, no retenido),
  no contra la muestra de 20. `classSample` (≤20) + `closureFor`.
- P2.2 protos + filtro JSON: `dynamicMethod` → `proto-model`;
  `isCleanJson` rechaza controles (caza el blob proto binario).
- P2.3 red nativa: `ElfInfo.soUrls` (≤20/lib) + contratos `[origen
  nativo]` + `touchers()` (red PARCIAL si el subgrafo toca APIs de red).
- P2.4 PermApiTable+: Cronet/javax/Volley/Retrofit/okhttp→INTERNET,
  PowerManager→WAKE_LOCK (YTM: WAKE_LOCK ahora visible); lookup de
  permisos del grupo sobre el subgrafo completo.
- P2.5 pantallas: clase llamada (`via X`) + candidato `~0x7f…` por rango
  (PARCIAL, no OK) cuando el sitio no se verifica.
- P2.6 JNI always-on: `scanSo` en una pasada (JNI+URLs) sin trigger.

Además: `keepDataLibEdge` conserva aristas lib de `dynamicMethod` /
`writeToParcel` (tope 500/dex) para ver modelos ofuscados; profundidad
de agrupador y cierre 3→5 con el mismo tope de 150 nodos (coste igual).

Medición YTM 81 MB: analyze 13,4 s, render 0,4 s, pico 140 MB
(≤ base 149), 64/48 m OK. Grafo 10304→11511 aristas. En APK propia
(TubeMusic): almacenamiento 2→25 OK. YTM sigue ≤3/8 por causas
estructurales (código ofuscado = prefijo lib, invisible al grafo;
tráfico por Cronet nativo; pantallas vía delegate ofuscado).

## P3 (atribución + semántica, verificado contra smali YTM)

Del descompilado apktool de YTM (37.365 smali) salieron 8 adaptaciones:

- P3.1 datos→función (`PhantomAttrib`): cada proto-model/parcelable
  se amarra a sus referenciadores vía aristas inversas ("referenciado
  por"); solo añade evidencia, Metric levanta estados sin cambios.
- P3.2 almacén huérfano (`PhantomAttrib`): helpers por clase-llamada,
  SQL un salto (loader → llamador propio, "llamado por").
- P3.3 pantallas (`PhantomUi`): cadena const-en-sitio → inflate →
  rango. `layoutViaInflate` prueba el patrón real YTM
  (`MusicActivity` infla 0x7f0e021c=layout/main_activity y entrega el
  View a `qb.setContentView(View)`); ARSC retenido (tope 20000)
  traduce id→nombre; sin id pero con vistas se declara
  "programática?" en vez de "?".
- Nombres (`PhantomNames.harvest`): etiquetas para clases ofuscadas
  desde const-strings Kotlin (.kt/.java y rutas). Sección
  "-- nombres". `MusicActivity` queda fuera (no ofuscada).
- Semántica (`PhantomNames.describe`): feature desde el manifest
  (MusicActivity → "Music") + 1 comportamiento por grupo
  (format-strings). Sección "-- semántica". No mueve la métrica.

Estimación YTM: 26% → 34–40% campos OK (pantallas +20–32,
datos +15–25, almacén +5–12); permisos/red/nativas sin cambio
(fuera del alcance P3).

## Auditoría (fases C–E, v0.4.1)

- `PhantomMetric.containsToken`: coincidencia por token (antes
  substring; "##-##" ya no casa con "lorem-##-ipsum").
- `PhantomNames.isObfuscated` delega en `DexParser.isShortName`
  (una sola definición; R8 3–5 minúsculas cubierta).
- `PhantomUi`/`PhantomTaint`: cachés de constantes y pares JNI por
  ejecución (antes re-derivaban por clase).
- `PhantomJniTest.detectaParNombreFirma`: par exacto + tamaño 1.
- Métrica sin cambio de umbrales; P3 verificado intacto.
