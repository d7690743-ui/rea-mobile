# OMEGA Fase B4 — Limpieza evidenciada en informe B3

Alcance: 3 mejoras salidas del informe real de YouTube Music generado con
el APK B3 (`informe_completo (5).txt`). Sin reescribir nada; cada una con
tests. El informe B3 ya validó el lote B3 (ratio 0.93, OIDs fuera, @2x
fuera, llama dedup, [manifest]/[arsc], deeplinks dedup).

## Precisión

- URLs: `trimUrl` recorta puntuación final pegada al citar
  (`...32658863).` → `...32658863`, `...NAOOOI.` → `...NAOOOI`) y cierres
  )]} desequilibrados; los balanceados tipo wiki `c_(d)` se conservan.
  Las 3 variantes fblitho (`...exception`, `...,`, `....`) colapsan en una
  línea vía el Set. El contador `urls=` sigue contando ocurrencias
  ("N URL(s) en strings"), igual que antes.
- Secretos alta: `isTokenLike` rechaza `//...` inicial (URLs relativas a
  protocolo como `//www.gstatic.com/...jpg`, que pasaba el alfabeto y la
  entropía). Un token base64 con `/` simple interior sigue pasando.

## Cobertura

- `[manifest]`: `ManifestChecks` añade a `components` las clases a nivel
  de `<application>` (`android:name` y `android:backupAgent`), que por no
  ser etiquetas activity/service/receiver/provider nunca se verificaban
  (caso: `MusicBackupAgent;->onCreate` sin marca en YT Music). Fluye por
  el `resolveDescriptor` existente; sin falsos positivos posibles.
