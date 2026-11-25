# OMEGA Fase D — Plan de búsqueda RAG

Alcance: adaptar `OMEGA_APK_RAG_Knowledge_Base.md` (vive en Descargas,
fuera del repo) para que el módulo de inteligencia sepa qué buscar en
cada APK y declare qué cubrió. Primer paso del roadmap K del RAG (§25):
perfil + retrieval exacto sobre evidencias propias, sin persistencia.

## Diseño

- `engine/SearchPlan`: utilidad estática sin estado. `classify` asigna
  perfil §19 (sencillo/mediano/grande/framework/ofuscado; el motor manda,
  luego ofuscación con el mismo umbral del hallazgo, luego tamaño).
  `planFor` ordena los 20 checks (§23) por perfil. `build` evalúa cada
  check con estados §0.1 derivados de los módulos existentes (FOUND,
  NOT_FOUND_IN_SCOPE, NOT_EXECUTED, UNSUPPORTED, PARTIAL…): taint y
  dinámico declaran UNSUPPORTED, fuentes NOT_EXECUTED (existe el módulo,
  no corre en `analyze`), nativas PARTIAL (inventario sin desensamblado).
  Cripto/web reutilizan `ClassRoles`.
- Integración en `ReaEngine`: sección `=== COBERTURA (perfil=X) ===` con
  `check=<id> <ESTADO> <detalle>`; `feedIntelPlan` añade un hallazgo
  `perfil` con el recuento (solo si el informe trae archivo analizado,
  para no declarar cobertura inexistente); `toJson` añade `profile` y el
  mapa `coverage`.

## Pruebas

`SearchPlanTest` (6): perfiles (incluido Brave→framework por libchrome
y YT→ofuscado por ratio), orden por perfil, cobertura vacía/con datos,
packer→ofuscado, malas. `ReaEngineTest.coberturaInformeYRegistro`:
sección, `[perfil]` y JSON. `puenteIntel` intacto.

## Auditoría (fases A–E, v0.4.1)

`SearchPlan` y la sección de cobertura: revisados, sin cambios
necesarios (estados declarados intactos, suite en verde).
