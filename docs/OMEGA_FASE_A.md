# OMEGA FASE A — Auditoría del repositorio (2026-11-22)

Inventario real sobre `master` (`a242470`): 18 motores Java (~5900 líneas),
UI Kotlin (~1240), 12 ficheros de tests (~54 pruebas), 2 docs de fases.
Dependencias: solo `jadx-core` + `jadx-dex-input` 1.5.2 (descompilar) y
JUnit 4 en tests. Sin red, sin nube. CI: `assembleDebug` + `testDebugUnitTest`.

## 1. Qué se reutiliza (no reescribir)

| Módulo OMEGA | Base existente | Estado |
|---|---|---|
| Code Reference Graph (B) | `DexCalls` aristas caller→callee + `DexParser` clases/métodos | Ampliar: DexCalls da lista plana; falta grafo consultable + herencia/interfaces |
| Flow Analyzer (C) | `IrBuilder` IR + bloques + sucesores (F3.1) | Ampliar: falta def-use entre bloques y taint origen→destino |
| App Structure (D) | `AxmlDecoder` manifest + `ManifestChecks` componentes | Ampliar: unir componente→clase→métodos de entrada |
| UI Reconstructor (D) | `AxmlDecoder` (sirve para layouts: también son AXML binario) + `ArscStrings` | Nuevo lector de `res/layout/*.xml` + mapa navegación |
| Feature Extractor (E) | `TrackerTable`, `PackerMarkers`, `PermApiTable`, `DexCalls` | Nuevo: reglas funcionalidad→evidencias |
| Network Mapper (F) | URLs/IPs/hosts de `ReaEngine.scanStrings` | Nuevo: endpoints + librería HTTP + método origen |
| Crypto Analyzer (F) | `SecretRules` (entropía) + `DexCalls` (llamadas) | Nuevo: tabla API crypto + flujo clave/IV/datos |
| Native Analyzer (G) | `NativeTable` (nombre) + `ApkSigBlock`-style ELF arch + `LibAppScan` | Ampliar: parser ELF (imports/exports/JNI/strings) |
| Correlación (H) | `ReaEngine.Finding` (sección/título/detalle/evidencia) + `DexCalls` + `ManifestChecks` | Nuevo: `intelligence` (este cambio) como modelo común |
| Blueprint (I) | `FullReport` TXT + `ApkReport.toJson()` | Ampliar: JSON/HTML estructurado por secciones |
| Dinámico (J) | Nada (solo `ArtDiag` de entorno) | Solo interfaces cuando toque; no ahora |

## 2. Qué falta (gaps reales)

- Modelo de hallazgo unificado con confianza, tipo de evidencia y
  relaciones → se crea en este cambio (`intelligence`, §4).
- Grafo consultable (llamantes/llamados por método, qué usa cada API).
- Data-flow entre bloques (def-use) y taint básico.
- Parseo de layouts y mapa de pantallas/navegación.
- Tablas crypto/red/JNI y sus detectores con evidencia de llamada.
- Parser ELF propio (cabecera, secciones, símbolos, JNI).
- Correlador permiso→componente→método→datos→destino.
- Generador Blueprint JSON/HTML consumible como especificación.
- APKs de prueba con comportamientos conocidos (§12 del plan).

## 3. Riesgos y límites medidos

- RAM: todo el motor usa topes (`DexParser` 20k strings/10k clases,
  `DexCalls` 20k aristas, JADX 15M caracteres, `FullReport` 20MB Java…),
  `largeHeap`, hilos de fondo y cancelación en JADX. No cargar DEX+smali+
  Java a la vez (ya se respeta: se libera antes de JADX).
- `try/catch`, bucles y SSA: pendientes (F3.2-F3.4); el IR actual cubre
  if/goto/switch verificados contra baksmali.
- Ofuscación: solo ratio heurístico; sin desofuscado.
- Termux: no compila APK (aapt2 glibc) → build en Actions vía `autopush.sh`.

## 4. Primera modificación (este cambio, aditiva)

Paquete `com.nexos.reamobile.intelligence`, sin tocar código existente:

- `IntelFinding`: los 12 campos del plan (id, categoría, descripción,
  fichero, clase, método, posición, evidencia, relacionados, confianza,
  tipo de evidencia, limitaciones). Java puro, nunca lanza.
- `IntelRegistry`: colector con tope (5000), ids `F-0001…`, consultas por
  categoría y clase. Java puro, nunca lanza.
- `IntelTest`: alta, ids, tope, filtros, nulos.
- Puente `ReaEngine.feedIntel`: vuelca los hallazgos clásicos al registro y
  `toText()` añade la sección `INTELIGENCIA` (visible en la app). Las fases
  B/C/H añadirán hallazgos propios con clase/método/evidencia.

Verificación: suite JVM local + `testDebugUnitTest` en CI.
