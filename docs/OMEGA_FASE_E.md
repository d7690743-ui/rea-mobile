# OMEGA Fase E — Análisis de flujo (def-use, constantes, SSA, inter, taint)

Alcance: cerrar el hueco raíz del plan OMEGA (Flow Analyzer C, §8 del RAG):
seguir datos dentro y entre métodos, sobre la IR existente y sin reescribir
nada. Cinco piezas + recolector, conectadas en este orden:

```
DEX → FlowScan → MethodIr por método (+ pool const-string)
  → DefUse (E1: cadenas def-use intra-bloque)
  → ReachConsts (E2: reaching + constantes en llamadas)
  → Ssa (E3: versiones + phis en joins)
  → InterProc (E5: resúmenes por método + callee por sitio)
  → Taint (E4: orígenes → sumideros, intra + inter un salto)
  → ReaEngine: sección FLUJO + hallazgos taint/flujo + JSON + check RAG
```

## Diseño

- `engine/FlowScan` (E0): recorre class_data como DexCalls y construye IR
  solo de métodos propios de ≤4000 units (tope 400 métodos); pool con los
  const-string referenciados (tope 5000, valor recortado a 500). Claves
  `Lcls;->nombre` como DexCalls; el primero gana entre dexes.
- `engine/DefUse` (E1): def/use por opcode Dalvik sobre MethodIr, encadenado
  exacto intra-bloque, ENTRY (-1) si el valor puede venir de fuera;
  move-result enlazado a su invoke (`resultOf`); `propagate` para taint.
- `engine/ReachConsts` (E2): lattice UNDEF/CONST/NAC con meet en joins +
  reaching con gen/kill y unión acotada (8 defs/reg); si un camino del join
  no define el registro se añade ENTRY. Pliegue solo entero (lit8/lit16,
  2addr, neg/not); heap y wide-pares → NAC. `callConsts`: constantes en
  args de invoke.
- `engine/Ssa` (E3): versión única por def (vR_K) + phi conservadora en
  joins con ≥2 reaching (fuentes = versiones o `entry`). Sin frontera de
  dominancia (documentado): puede sobrar alguna phi, nunca falta.
- `engine/InterProc` (E5): `calleesAt` resuelve callee por (llamador, pos)
  contra aristas reales; `Summary` con regs de entrada (leídos antes de
  definirse), `retMayCarryEntry`, llamadas con constArgs y `sinksFromEntry`
  (vía `SinkMatcher`, sin ciclo con Taint).
- `engine/Taint` (E4): tablas origen/sumidero por nombre + herencia por
  supers (tope 8); intra exacto con procedencia; inter de un salto
  (arg marcado → sinksFromEntry del callee; retorno sobre-aproximado con
  re-inspección del llamador). Topes 200 métodos / 50 flujos.

## Integración

- `ReaEngine.ApkReport`: `flowIrs`, `flowDex`, `flowStrings`, `flowTruncated`;
  `collectFlow` corre por dex dentro de `collectOwnCalls`.
- Informe: `=== FLUJO (metodos=M defs=D consts=C taint=T) ===` con líneas
  `const=<llamador>@+<pos> v<R>=<texto>` y `taint=<origen> ~> <sumidero>
  en <método> [inter]`; `toJson` añade `flowMethods/flowDefs/flowTruncated/
  flowConsts/taintFlows`.
- Registro OMEGA: `feedIntelFlow` crea hallazgos `taint` (tope 20) y
  `flujo` para constantes en llamadas sensibles (tope 10), confianza MEDIA,
  tipo STATIC y limitación obligatoria de ejecución no observada.
- `SearchPlan` check `taint`: FOUND si hay flujos, PARTIAL si hubo métodos
  sin flujos, NOT_EXECUTED sin IR (antes: UNSUPPORTED fijo).
- Limitación actualizada: flujo parcial best-effort (inter un salto, sin
  heap ni reflexión).

## Pruebas

`DefUseTest` (5), `ReachConstsTest` (5), `SsaTest` (3), `InterProcTest` (4),
`TaintTest` (5), `FlowScanTest` (3) sobre IR sintética + DEX sintético;
`ReaEngineTest.flujoInformeYRegistro` (sección, `[taint]`, JSON) y
`SearchPlanTest.taintEvaluaFlujo` (PARTIAL). Se actualizaron 2 assertions
que fijaban `taint UNSUPPORTED` (cambio de contrato intencionado).
