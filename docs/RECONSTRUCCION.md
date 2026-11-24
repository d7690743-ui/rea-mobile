# RECONSTRUCCIÓN — Paquete de conocimiento para que una IA reimplemente funciones

Cambio de criterio: REA no reconstruye el APK; produce conocimiento
estructurado suficiente para que una IA reconstruya sus funciones.
El éxito deja de medirse en paridad forense (baksmali/JADX) y pasa a
medirse en completitud reconstructiva por función.

## Función reconstruible (definición)

Una función está reconstruible cuando el paquete le asigna, con
evidencia citada (dex/clase/método/offset o entrada del APK):

```
funcion = id estable + nombre probable + entradas + pantallas +
  llamadas + datos + permisos + red + almacenamiento + nativas +
  estado por campo (OK/PARCIAL/FALTA) + confianza + límites
```

Campos mínimos por función:

- `entradas`: componentes del manifest + métodos verificados en grafo.
- `pantallas`: layouts/Compose que muestra + navegación (quién la abre).
- `llamadas`: subgrafo propio + framework tocado, con consts de flujo.
- `datos`: modelos/parcelables/prefs/schemas que lee y escribe.
- `permisos`: declarados + amparo (qué API los usa, desde qué método).
- `red`: endpoints + método + payload observado o inferido (no URL suelta).
- `almacenamiento`: SQLite/prefs/ficheros con esquema cuando exista.
- `nativas`: .so + símbolos JNI implicados, si la función los toca.

Sin agrupación por función, las piezas sueltas (URLs, consts, aristas)
no bastan: el paquete debe enlazarlas bajo cada función.

## Formato del paquete

- Artefacto primario: JSON máquina-legible con IDs estables
  (`F-####` para hallazgos, `FN-##` para funciones) y punteros a
  evidencia. El .txt pasa a vista humana, no a fuente.
- Cada campo declara estado honesto estilo §0.1 RAG
  (FOUND/PARTIAL/NOT_FOUND_IN_SCOPE/NOT_EXECUTED/UNSUPPORTED) y
  nunca afirma ausencia total desde un muestreo.
- Topes y recortes se declaran por sección (ya se hace en FLUJO,
  GRAFO, RED); el consumidor IA debe poder saber qué no vio.

## Métrica de completitud

Por función: `completitud = campos OK / 8 campos mínimos`.
Por APK: distribución (p.ej. "12 funciones ≥6/8, 30 funciones ≤3/8").
Un informe sin esta métrica no puede afirmar que es suficiente.

## Mapeo módulos actuales → campos

```
entradas      ← ManifestChecks + RefGraph + AlfaUi (192 en YTM)
pantallas     ← AlfaUi layouts (0 en YTM: splits/Compose) — HUECO
llamadas      ← RefGraph + DexCalls + FlowScan/DefUse/ReachConsts
datos         ← (sin módulo) — HUECO
permisos      ← PermApiTable + AlfaCorr (amparo a 1 salto)
red           ← StringRefs/LogicNet URLs (29 sueltas en YTM) — PARCIAL
almacenamiento← (sin módulo) — HUECO
nativas       ← AlfaElf/AlfaJni inventario (24 .so, 0 JNI) — PARCIAL
agrupación    ← (sin módulo: ClassRoles da roles, no funciones) — HUECO
exportación   ← toJson existe pero no sale del teléfono — HUECO
```

## Huecos ordenados por impacto (evidencia: caso YTM)

1. Exportar el JSON del paquete (hoy solo sale .txt).
2. Agrupador funcional: entry→pantalla→subgrafo→datos→red (FN-##).
3. UI real: resolver setContentView + Compose (0 pantallas en YTM).
4. Contratos de red: endpoint+método+payload por llamador.
5. Almacenamiento: SQLite/prefs/schemas por función.
6. Nativo: RegisterNatives + JNI dinámico (jni=0 en 24 libs YTM).
7. Taint multi-salto + reflexión (hoy 1 salto, 0 flujos en YTM).

## Roadmap propuesto

- R1: exportar `paquete.json` junto a `informe_completo.txt` (mismo
  contenido toJson + IDs + estados + métrica por función aunque sea
  vacía al inicio).
- R2: agrupador funcional mínimo (manifest→grafo→red→permisos).
- R3+: pantallas, contratos de red, almacenamiento, nativo, taint.

## Caso de referencia

YouTube Music `com.google.android.apps.youtube.music`, informe del
24-nov (build e2e15cea, 987 KB, 28.235 líneas): 6 dex, 37.365 clases,
274.656 métodos, ofuscación 0.93, 121 clases propias con Java, 147
hallazgos intel, grafo 4.392/10.304, 192 entradas, 24 .so.
Buen inventario forense; insuficiente para reconstruir (0 pantallas,
URLs sin método, sin agrupación funcional, sin JSON).
Ruta: `REA-Mobile/com_google_android_apps_youtube_music/informe_completo (2).txt`
en Descargas compartida.
