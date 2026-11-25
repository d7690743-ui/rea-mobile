# REA APK Authenticity Engine v1.0

Motor independiente de verificación de autenticidad, firma y procedencia
de APK. Entrada: un APK. Salida: `AuthResult.Report` (JSON
`rea-authenticity-v1` + sección TXT). Independiente de OMEGA, ALFA, ECO y
PHANTOM: no los importa; reutiliza solo `ApkSigBlock`, `AxmlDecoder` y
`ManifestChecks`.

```
APK → Firma → Identidad → Sello → Rotación → Baseline → Repack → Veredicto
      (apksig 8.7.3 primario + verificador interno de respaldo)
```

## Capas (`engine/auth/`)

| Capa | Clase | Qué demuestra |
|---|---|---|
| 1 Firma | `AuthSignature` | v1/v2/v3/v3.1 presentes + verificados, integridad, firmantes múltiples, cotas SDK. Respaldo sin apksig: digest AOSP por bloque + firma JCA sobre signed-data (PSS/PKCS1/ECDSA/DSA). v1 sin apksig = UNKNOWN. |
| 2 Identidad | `AuthCert` + `AuthAllowlist` | SHA-256/SHA-1/MD5, DN, serie, validez, algoritmo, huella de clave. Allowlist JSON versionada (`rea-allowlist-v1`), multicertificado, históricos, linajes. Sin allowlist = UNKNOWN. El DN nunca acredita. |
| 3 Sello | `AuthProvenance` | Presencia, validez criptográfica, cert del sello, identidad vs referencia, atribución Play (requiere sello válido + identidad confiable). |
| 4 Rotación | `AuthRotation` | proof-of-rotation v3/v3.1: presencia (atributo `0x3ba06f8c`), validez, cadena oldest→newest, clave observada (la firmante real, nunca inferida del SDK), coincidencia con linaje oficial (subsecuencia). |
| 5 Baseline | `AuthBaseline` + `AuthManifest` | Referencias exactas (`rea-baseline-v1`): APK, DEX, nativas, manifest normalizado, permisos, componentes, exportados, splits, variante/ABI/densidad, esquemas, flags. Solo compara paquete+versión+variante exacta. Hashes por streaming (topes 512MB/32MB). |
| 6 Repack | `AuthRepack` | Indicador observado vs diferencia confirmada vs modificación demostrada. `allowBackup`/splits/v1 solo anomalía con referencia. |
| 7 Veredicto | `AuthVerdict` | OFFICIAL (identidad + firma + sin discrepancias) / NOT_OFFICIAL (discrepancia confirmada con linaje+variante) / SUSPICIOUS (contradicciones, fallos cripto, modificaciones) / UNKNOWN. Confianza HIGH/MEDIUM/LOW por calidad de evidencia, sin puntos. Play es dimensión aparte. |

Rango apksig: plataformas 24–100000 (= minSdk de REA; con 1, apksig
exige v1 a APKs v2/v3 puros y suprime el sello — verificado empíricamente).

## Referencias importables

- `assets/rea_allowlist.json` (`rea-allowlist-v1`, vacío): `entries[]`
  con `package` + `certs[{sha256, pubkey_sha256?, historic?, versions?,
  variant?}]`, más `lineages[{package, chain[]}]`.
- `assets/rea_baseline.json` (`rea-baseline-v1`, vacío): `entries[]` con
  paquete, versión, variante, abis, densidades, canal, fecha, hashes y
  listas. Nunca comparar versiones/variantes distintas (el motor lo impide).
- `assets/rea_trusted_stamps.json`: `sha256[]` de sellos confiables.
- Actualización sin tocar el motor: sustituir los JSON (misma `schema`).

## Integración

- `ReaEngine.analyze(apk[, options])`: estático + `auth`; `analyzeStatic`
  solo estático (lo usa la prioridad PHANTOM para no pagar autenticidad).
- TXT: `AUTENTICIDAD Y PROCEDENCIA` tras FIRMA (no la sustituye).
- JSON: clave `authenticity` en `paquete.json` (aditiva; informes viejos
  siguen legibles).
- ZIP: `rea/autenticidad.json` vía `putTextTracked` (respeta tope total y
  notas; secretos ya enmascarados en origen).
- UI: botón Autenticidad → diálogo de 7 indicadores en texto (UNKNOWN =
  "no comprobado", nunca error) → detalle con evidencia por indicador.

## Límites declarados

- Sin apksig (forzado o ausente): v1, validez de sello, validez/cadena de
  linaje y capacidades = UNKNOWN con motivo; digests + firmas JCA v2/v3 sí
  se verifican.
- `observed_key` sin apksig = firmante del bloque (correcto), pero la
  cadena del linaje no se extrae.
- Manifest normalizado débil (colapsa blancos; reordenamientos cambian
  el hash — documentado en el formato).
- Sin servicio remoto de referencias (fuera de alcance v1.0).
- Construcción Gradle/lint/Kotlin: verifica en CI (Termux no corre aapt2);
  aquí se verificó el árbol Java + tests vía javac/JUnit directos.

## Pruebas

`engine/auth/`: `AuthFixture` (claves RSA + DER propio + firmado real
apksig incl. linaje por reflexión y sello) y 7 suites, 45 pruebas: los 20
escenarios obligatorios + matriz de veredictos + regresión de informe/ZIP.
Suite total: 311 en verde (JVM local; CI añade lint + APKs).
Medido: YTM 81MB → 12 s, 26MB heap retenido; tubemusic 27MB → 6 s, 13MB.
