# ALFA-1 — Nativo/ELF + puente JNI

Alcance: inventariar el código nativo del APK (qué .so trae, qué exporta,
qué necesita) y unirlo con el DEX por el único puente observable sin
desensamblar: los símbolos `Java_paquete_Clase_metodo` y `JNI_OnLoad`.

```
.so → AlfaElf.parse (ventanas head+tail, sin cargar el .so entero)
  → ElfInfo (arch, tipo, imports/exports, needed, JNI_OnLoad?)
  → AlfaJni.decode (símbolo → clase+método Java)
  → AlfaJni.link (¿llama alguien a ese método? vía RefGraph)
  → ReaEngine: sección NATIVO + JSON + intel + SearchPlan
```

## Diseño

- `engine/AlfaElf`: parsea cabecera ELF32/64, program headers y la
  dinámica (DT_NEEDED, DT_SONAME, strtab/symtab si caen en ventana).
  Ventanas 4MB+2MB, tope 150MB por .so y 30 libs; lo que cae fuera se
  marca `[parcial]`, nunca se inventa.
- `engine/AlfaJni`: `decode` traduce el mangling JNI (incluye `_1`
  sobrecargas y `_0XXXX` unicode); `link` busca llamadores del método
  Java en el grafo OMEGA. Sin llamador → `[sin llamadas]`.
- Conexión: `alfaElfs` en ApkReport, `summarizeAlfaJni`, sección
  `NATIVO (libs=N jni=M)`, JSON `elfParsed`/`jniLinks`, intel
  `nativo`/`jni` (MEDIA, "ejecución no observada"), check RAG
  `nativas` en SearchPlan (PASS si hay JNI con llamadas, si no
  PARTIAL/FAIL honesto).

## Límites declarados

- Sin desensamblado: de una función nativa solo se conoce el nombre.
- `RegisterNatives` (registro dinámico) es invisible: JNI real puede
  quedar sin puente. El informe lo dice, no lo oculta.
- .so gigante o stripped → `[parcial]`: conteos imp/exp en 0 con marca.

## Pruebas

`AlfaElfTest` (ELF32/64 mínimos construidos a mano, truncados, basura),
`AlfaJniTest` (mangling, sobrecargas, link con/sin llamador),
`ReaEngineTest.nativoInformeYRegistro` (sección + JSON + intel).
Verificado en YTM real: 24 libs, 1 con JNI_OnLoad, resto parcial.
