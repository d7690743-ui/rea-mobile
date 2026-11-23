# Fase 3 — Motor propio de reconstrucción (plan por fases)

Objetivo a largo plazo: reconstruir Java-like con motor propio, sin depender
de JADX. Base existente: `SmaliDumper` (decode total de Dalvik) y DEX
sintéticos (`SmaliExtractTest.buildTestDex`).

Regla: ninguna fase se declara implementada sin prueba reproducible en CI.

## F3.1 Representación intermedia + bloques básicos

- Parsear instrucciones a IR (opcode, registros, literales, refs).
- Partir en bloques básicos por saltos/etiquetas.
- Test: dex sintético con if/goto, bloques esperados exactos.

## F3.2 CFG + tipos de registros

- Grafo de flujo con sucesores por bloque.
- Propagación simple de tipos (resultados de invoke, const).
- Test: CFG esperado + tipos inferidos en 3 métodos sintéticos.
- Estado: implementado. CFG ya venía de F3.1 (`IrBuilder.succs`);
  `IrTypes.infer` propaga tipos por registro sensible al flujo (merge en
  joins, punto fijo acotado): const→I/J/String/Class, invoke→retorno vía
  `Resolver`, move/move-result/new-instance/check-cast/instance-of/
  array-length. Tests: `IrTypesTest` (línea, merge, bucle, malas).

## F3.3 SSA-lite (cuando sea viable)

- Renombrado SSA en métodos sin excepciones ni sincronizados.
- Test: variables versionadas correctas; fallback a no-SSA si falla.

## F3.4 Estructuración

- if/else, bucles (while/for/do), switch, try/catch por patrones.
- Una construcción por entrega, cada una con dex sintético dedicado.
- Test: patrón reconocido + código estructurado esperado.

## F3.5 Emisor Java-like + confianza

- Emisor desde IR estructurada con importes y firmas.
- Indicador de confianza por método (completo/parcial/fallback smali).
- Test: corpus fijo sintético comparado contra salida esperada grabada;
  comparación manual contra JADX Desktop documentada, no automatizada.

## Notas

- Todo corre on-device en hilos de fondo, por lotes y con topes.
- El motor propio convive con JADX: cada visor indica su fuente.
