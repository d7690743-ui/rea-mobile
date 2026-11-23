# OMEGA Fase B5 — Microfix recorte de URLs

Alcance: 1 corrección sobre el B4, evidenciada en el informe real de
YouTube Music generado con el APK B4 (`informe_completo (6).txt`).

## Precisión

- URLs: `trimUrl` ya no recorta el `?` final (set `[.,;:!?]` → `[.,;:!]`
  + cierres desequilibrados). El B4 corrompía la URL-patrón regex de
  `play.google.com` (`...(.+)?)?` → `...(.+)?)`), donde el `?` final es
  parte del patrón (grupo opcional), no puntuación pegada. Una query
  vacía legítima también puede terminar en `?`.
