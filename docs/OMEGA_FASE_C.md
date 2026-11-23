# OMEGA Fase C — Roles por clase

Alcance: resumir qué hace cada clase propia a partir de las llamadas
sensibles que emite (las que ya detecta DexParser, con herencia por
supers). Sin reescribir nada; agregado sobre RefGraph.

## Diseño

- `engine/ClassRoles`: utilidad estática sin estado (como LogicNet).
  `roleFor` mapea cada prefijo suspicious a una etiqueta corta (red,
  cripto, reflexion, proceso, web, telefonia, ubicacion, contactos,
  biometrico, carga-dinamica, nativa, admin, accesibilidad; resto a
  "sistema"). `assign` recorre las aristas del grafo, filtra propias por
  `pkgSlash` (null/vacío = todas) y devuelve por clase sus roles con
  conteo + hasta 3 evidencias, ordenados por conteo. Tope 200 clases.
- Integración en `ReaEngine`: sección `=== ROLES (N) ===` con líneas
  `rol=<clase> <rol> x<n> [evidencias]`; `feedIntelRoles` crea un
  hallazgo `rol` por (clase, rol) con confianza MEDIA, tipo STATIC y la
  limitación de ejecución no observada (tope 20); `toJson` añade el mapa
  `"roles":{clase:[roles]}`. `pkgSlashOf` comparte la derivación del
  filtro de propias.

## Pruebas

`ClassRolesTest` (4): tabla, agregación por clase, herencia via supers +
filtro de propias, malas. `ReaEngineTest.rolesInformeYRegistro`: sección,
registro `[rol]` y JSON.
