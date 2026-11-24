# ALFA-3 — Correlador + Blueprint (permiso→API→método→destino)

Alcance: el mapa funcional del APK en una sección: cada URL/destino
ligada al método que la usa y al permiso que ampara la API tocada.
Reutiliza StringRefs, RefGraph, PermApiTable y urls ya construidos;
no re-parsea nada (coste ~0, memoria ~0 salvo `callerPerm`).

```
urls × StringRefs.usersOf[Containing] → métodos usuario (tope 5)
  → callerPerm (mapa exacto llamador→"permiso|api", tope 4000)
  → un salto: ayudantes del usuario en el mapa (tope 25)
  → respaldo: amparo directo de callees en el grafo
  → AlfaCorr.Chain → sección BLUEPRINT + JSON + intel
```

## Diseño

- `engine/AlfaCorr.correlate`: 30 URLs / 50 cadenas. `usersOf` exacto
  primero, `usersOfContaining` después (las URLs suelen ser subcadenas
  de literales). Permiso en 3 pasos (mapa, un salto, grafo).
- `ReaEngine.callerPerm`: se llena en `collectOwnCalls`, en el mismo
  bucle que ya calculaba `usedPerms` (primera "permiso|api" por
  llamador). Hizo falta porque el grafo solo guarda aristas propias y
  las APIs con permiso son framework (fuera del grafo).
- `summarize`: una línea `permiso=X[declarado][riesgo] api=… metodo=…
  destino=… (origen)`. `hostOf` best-effort para agrupar.
- Conexión: sección `BLUEPRINT (cadenas=N riesgo=M)` + línea mapa,
  JSON `corrChains`, intel `correlacion` (MEDIA si permiso declarado,
  si no LOW; "correlación estática por literal compartido; ejecución
  no observada"). Sin check RAG nuevo: Blueprint es vista, no puerta.

## Límites declarados

- Correlación, NO flujo verificado: compartir literal no demuestra que
  el dato viaje a ese destino (Taint de OMEGA cubre el flujo real).
- Un solo salto a ayudantes; cadenas más largas quedan en `permiso=?`.
- `permiso=?` / `metodo=?` es dato honesto (ofuscación, truncados,
  URLs documentales), no fallo: la cadena se muestra igual.

## Pruebas

`AlfaCorrTest` (cadena completa, URL en literal, no declarado, mapa
primario, un salto, basura), `ReaEngineTest.blueprintInformeYRegistro`.
Verificado real: Ventas FB 7 cadenas INTERNET→WebView.loadUrl→URLs de
Facebook; YTM 24 cadenas honestas con `?` donde no hay evidencia.
Suite total: 162 tests OK (salvo JadxAdapterTest, pre-existente por
entorno sin librería real).
