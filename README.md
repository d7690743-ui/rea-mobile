# REA Mobile

Análisis estático de APK 100% on-device, inspirado en
[REA (Reverse Engineer Anything)](https://github.com/morluto/rea) (MIT) y su fork
solo-Android [REA-ReverseEngineerAndroid](https://github.com/Hubupup/REA-ReverseEngineerAndroid).
Código del motor escrito desde cero en Java/Kotlin; dependencias: JADX
(descompilar) + apksig oficial (verificar firmas).

## Novedades v0.5

- REA APK Authenticity Engine (`engine/auth`, independiente de OMEGA/ALFA/
  PHANTOM): verificación criptográfica v1/v2/v3/v3.1 con apksig 8.7.3 +
  respaldo interno (digest AOSP + firma JCA), identidad de firmante con
  allowlist versionada, Source Stamp, linaje de rotación, baseline oficial
  importable, indicadores de repack y veredicto OFFICIAL/NOT_OFFICIAL/
  SUSPICIOUS/UNKNOWN con confianza por calidad de evidencia.
- Informe: nueva sección `AUTENTICIDAD Y PROCEDENCIA` (amplía FIRMA),
  `authenticity` en `paquete.json`, `rea/autenticidad.json` en el ZIP y
  botón Autenticidad con evidencia por indicador. Lo no comprobado es
  UNKNOWN, nunca acusación: 45 pruebas nuevas, 311 en total en verde.

## Novedades v0.4

- Secretos en dos niveles: reglas por formato estilo Gitleaks + entropía
  de Shannon (`SecretRules`); alta confianza también en Java descompilado.
- Llamadas de código propio (`DexCalls`): qué API sensible invoca cada
  clase + permisos usados frente a declarados (`PermApiTable`).
- Firma v2/v3: certificado del firmante desde el bloque de firma
  (`ApkSigBlock`, esquema + SHA-256 + sujeto).
- Nativas clasificadas (`NativeTable`), escaneo de `libapp.so` en apps
  Flutter (`LibAppScan`), trackers (`TrackerTable`) y protectores
  (`PackerMarkers`).
- Manifest: autoarranque, permisos intrusivos, exportados, deep links e
  higiene (`ManifestChecks`); resumen de una línea al inicio del informe.
- Botón Compartir ZIP (`ZipShareProvider`, solo framework).

## Novedades v0.3

- Adaptador JADX por lotes: filtro por paquete, tope de clases y progreso
  cancelable (`JadxAdapter.decompileFiltered`).
- Extracción incluye `rea/JAVA/` con las clases propias descompiladas.
- Visor de código: explorador de clases, pestañas Smali/Java, búsqueda en
  lista y en código, exportación e indicador de confianza.
- Plan del motor propio en `docs/FASE3_MOTOR_PROPIO.md` (por fases, con tests).

## Novedades v0.2

- Smali on-device de las clases propias (desensamblador Dalvik propio, best-effort).
- Extracción a ZIP: árbol completo + `manifest.xml` decodificado + smali + strings
  + informe. Se guarda en Descargas/REA-Mobile.
- Test unitario mantenido (`SmaliExtractTest`) que se ejecuta en Actions.

## Qué cubre el informe (ingeniería inversa estática)

- Identidad: nombre, tamaño, MD5/SHA-1/SHA-256, package.
- Manifest decodificado (parser AXML propio): permisos, actividades, servicios,
  receptores, proveedores + extracto XML.
- Ficha de Android (PackageManager): versiones, SDK, componentes, huellas de firma.
- DEX: nº de strings/clases/métodos, stats de API por paquete, heurística de
  ofuscación, muestra de métodos y APIs sensibles.
- Recursos: nº de strings de `resources.arsc`, conteos de `res/` y `assets/`.
- Nativas: inventario de `.so` con arquitectura por cabecera ELF.
- Firma: certificados X.509 de `META-INF` (sujeto y serie).
- Indicios: URLs, IPs, emails y posibles secretos en strings (DEX + ARSC).
- Cada hallazgo trae su evidencia; el informe cierra con limitaciones y unknowns,
  al estilo REA.

## Qué se adaptó de REA y qué no

| Familia REA | REA Mobile |
|---|---|
| `android` (paquete, manifest, clases, métodos) | Sí: AXML propio + PackageManager + parser DEX |
| `artifact` (inventario, firmas) | Sí: ZIP + hashes + X.509 + huellas |
| `apktool` (recursos) | Parcial: pool ARSC + árbol res/assets, sin recompile |
| `native` (ELF) | Parcial: inventario + arquitectura, sin desensamble |
| `flutter` | Solo detección (libflutter/libapp) |
| `adb`, `frida`, `jeb`, `direct`, `enhanced` | No: requieren PC, adb, Ghidra/IDA o runtime |
| `application`, `session` (evidencia, unknowns) | Sí: informe con evidencia, limitaciones y unknowns |

Fuera del MVP: descompilación a Java real (requiere JADX + JDK completo),
xrefs completas entre bytecode, análisis dinámico y reconstrucción total
(necesita aapt2). El smali on-device cubre lectura de lógica; la extracción
cubre recursos y árbol.

## Compilación

No compila en Termux nativo (aapt2 es glibc). Se compila en GitHub Actions
con `bash autopush.sh "mensaje"` (misma toolchain que apk-template:
Gradle 8.9, AGP 8.7.3, Kotlin 1.9.24, Java 17, SDK 35, minSdk 24).

## Créditos

- [JADX](https://github.com/skylot/jadx) (Apache License 2.0): descompilación
  DEX a Java mediante `jadx-core` + `jadx-dex-input`, sin GUI ni CLI.
- Inspirado en [REA](https://github.com/morluto/rea) (MIT) y su fork
  solo-Android.

## Uso responsable

Analiza solo APKs que te pertenecen o para los que tienes autorización expresa.
