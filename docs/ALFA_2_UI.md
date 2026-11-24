# ALFA-2 — UI/navegación (layouts + entradas verificadas)

Alcance: mapa de pantallas del APK y de sus puntos de entrada reales:
qué layouts existen, qué handlers `onClick` declaran, y qué métodos de
clases del manifest tienen llamadas en el grafo (entradas verificadas).

```
res/layout/*.xml → AxmlDecoder (el existente, sin duplicar)
  → AlfaUi.parseLayout (vistas, ids, onClick, vistas custom, includes)
  → AlfaUi.verifiedEntries (manifestClasses ∩ llamadores del grafo)
  → AlfaUi.handlerCallers (handler → métodos por nombre)
  → ReaEngine: sección UI + JSON + intel
```

## Diseño

- `engine/AlfaUi.Screen`: un layout = nombre, nº vistas, ids (tope 50),
  handlers onClick, vistas custom (paquete propio → código), includes.
  Parser lineal best-effort sobre el XML decodificado; tope 200 layouts
  y 1MB por layout.
- `verifiedEntries`: una clase del manifest solo es "entrada" si algún
  método suyo aparece como llamador en RefGraph. Sin llamadas en el
  grafo no hay entrada (criterio OMEGA: evidencia citada).
- `handlerCallers`: une handler↔método por nombre (aproximado, honesto:
  intel `ui` en confianza LOW + "layout↔actividad no resuelto").
- `exportedDescriptors`: normaliza `manifestExported` ("activity:com.x")
  a descriptores (`Lcom/x;`) para marcar `[exportada]` en entradas.
- Conexión: `alfaScreens` en ApkReport, `summarizeAlfaEntries`, sección
  `UI (pantallas/handlers/entradas)`, JSON `uiScreens`/`uiEntries`/
  `uiHandlers`, intel `entrada` (MEDIA) y `ui` (LOW).

## Límites declarados

- `setContentView` NO se resuelve: no se afirma qué actividad muestra
  qué layout (requeriría flujo de enteros por recursos, fuera de
  alcance; documentado en `limitations` del informe).
- Sin res/layout (splits, Compose puro) → `pantallas=0`, sin error.

## Pruebas

`AlfaUiTest` (layout sintético, entradas, handlers, exportados, basura),
`ReaEngineTest.uiInformeYRegistro` (sección + JSON + intel).
Verificado real: YT WebView 1 pantalla + 16 entradas; Ventas FB igual;
YTM base 0 pantallas (layouts en splits) + 192 entradas.
