#!/bin/sh
# Push en un paso de REA Mobile.
# Uso: bash autopush.sh "mensaje del commit"
set -e
cd "$(dirname "$0")"
MSG="${1:-REA Mobile}"
git add settings.gradle build.gradle gradle.properties .gitignore \
  gradle/debug.keystore gradle/wrapper/gradle-wrapper.jar gradle/wrapper/gradle-wrapper.properties \
  gradlew gradlew.bat \
  app/build.gradle app/proguard-rules.pro \
  app/src/main/AndroidManifest.xml \
  app/src/main/res/values/strings.xml \
  app/src/main/java/com/nexos/reamobile/MainActivity.kt \
  app/src/main/java/com/nexos/reamobile/ZipShareProvider.java \
  app/src/main/java/com/nexos/reamobile/engine/AxmlDecoder.java \
  app/src/test/java/com/nexos/reamobile/engine/AxmlDecoderTest.java \
  app/src/main/java/com/nexos/reamobile/engine/DexParser.java \
  app/src/main/java/com/nexos/reamobile/engine/ArscStrings.java \
  app/src/main/java/com/nexos/reamobile/engine/ReaEngine.java \
  app/src/main/java/com/nexos/reamobile/engine/SmaliDumper.java \
  app/src/test/java/com/nexos/reamobile/engine/SmaliExtractTest.java \
  app/src/main/java/com/nexos/reamobile/engine/JadxAdapter.java \
  app/src/test/java/com/nexos/reamobile/engine/JadxAdapterTest.java \
  app/src/main/java/com/nexos/reamobile/engine/ArtDiag.java \
  app/src/main/java/com/nexos/reamobile/engine/IrBuilder.java \
  app/src/test/java/com/nexos/reamobile/engine/IrBuilderTest.java \
  app/src/main/java/com/nexos/reamobile/engine/JavaHarvest.java \
  app/src/test/java/com/nexos/reamobile/engine/JavaHarvestTest.java \
  app/src/main/java/com/nexos/reamobile/engine/FullReport.java \
  app/src/test/java/com/nexos/reamobile/engine/FullReportTest.java \
  app/src/main/java/com/nexos/reamobile/intelligence/IntelFinding.java \
  app/src/main/java/com/nexos/reamobile/intelligence/IntelRegistry.java \
  app/src/test/java/com/nexos/reamobile/intelligence/IntelTest.java \
  app/src/main/java/com/nexos/reamobile/engine/RefGraph.java \
  app/src/test/java/com/nexos/reamobile/engine/RefGraphTest.java \
  app/src/main/java/com/nexos/reamobile/engine/LogicNet.java \
  app/src/test/java/com/nexos/reamobile/engine/LogicNetTest.java \
  app/src/main/java/com/nexos/reamobile/engine/StringRefs.java \
  app/src/test/java/com/nexos/reamobile/engine/StringRefsTest.java \
  docs/OMEGA_FASE_A.md \
  docs/OMEGA_FASE_B.md \
  docs/OMEGA_FASE_B2.md \
  docs/OMEGA_FASE_B3.md \
  docs/OMEGA_FASE_B4.md \
  docs/OMEGA_FASE_B5.md \
  docs/OMEGA_FASE_C.md \
  app/src/main/java/com/nexos/reamobile/engine/ClassRoles.java \
  app/src/test/java/com/nexos/reamobile/engine/ClassRolesTest.java \
  app/src/main/java/com/nexos/reamobile/engine/IrTypes.java \
  app/src/test/java/com/nexos/reamobile/engine/IrTypesTest.java \
  docs/OMEGA_FASE_D.md \
  app/src/main/java/com/nexos/reamobile/engine/SearchPlan.java \
  app/src/test/java/com/nexos/reamobile/engine/SearchPlanTest.java \
  docs/OMEGA_FASE_E.md \
  app/src/main/java/com/nexos/reamobile/engine/DefUse.java \
  app/src/test/java/com/nexos/reamobile/engine/DefUseTest.java \
  app/src/main/java/com/nexos/reamobile/engine/ReachConsts.java \
  app/src/test/java/com/nexos/reamobile/engine/ReachConstsTest.java \
  app/src/main/java/com/nexos/reamobile/engine/Ssa.java \
  app/src/test/java/com/nexos/reamobile/engine/SsaTest.java \
  app/src/main/java/com/nexos/reamobile/engine/InterProc.java \
  app/src/test/java/com/nexos/reamobile/engine/InterProcTest.java \
  app/src/main/java/com/nexos/reamobile/engine/Taint.java \
  app/src/test/java/com/nexos/reamobile/engine/TaintTest.java \
  app/src/main/java/com/nexos/reamobile/engine/FlowScan.java \
  app/src/test/java/com/nexos/reamobile/engine/FlowScanTest.java \
  docs/MEMORIA.md \
  app/src/main/java/com/nexos/reamobile/engine/DexStrings.java \
  app/src/main/java/com/nexos/reamobile/engine/DexTypes.java \
  app/src/test/java/com/nexos/reamobile/engine/DexStringsTest.java \
  app/src/test/java/com/nexos/reamobile/engine/DexParserTest.java \
  app/src/test/java/com/nexos/reamobile/engine/ReaEngineTest.java \
  app/src/main/java/com/nexos/reamobile/engine/SecretRules.java \
  app/src/main/java/com/nexos/reamobile/engine/DexCalls.java \
  app/src/main/java/com/nexos/reamobile/engine/PermApiTable.java \
  app/src/main/java/com/nexos/reamobile/engine/ApkSigBlock.java \
  app/src/main/java/com/nexos/reamobile/engine/NativeTable.java \
  app/src/main/java/com/nexos/reamobile/engine/LibAppScan.java \
  app/src/main/java/com/nexos/reamobile/engine/TrackerTable.java \
  app/src/main/java/com/nexos/reamobile/engine/PackerMarkers.java \
  app/src/main/java/com/nexos/reamobile/engine/ManifestChecks.java \
  app/src/test/java/com/nexos/reamobile/engine/SecretRulesTest.java \
  app/src/test/java/com/nexos/reamobile/engine/DexCallsTest.java \
  app/src/test/java/com/nexos/reamobile/engine/ApkSigBlockTest.java \
  app/src/test/java/com/nexos/reamobile/engine/TablesTest.java \
  app/src/test/java/com/nexos/reamobile/engine/LibAppScanTest.java \
  app/src/test/java/com/nexos/reamobile/engine/ManifestChecksTest.java \
  app/src/main/java/com/nexos/reamobile/engine/AlfaElf.java \
  app/src/test/java/com/nexos/reamobile/engine/AlfaElfTest.java \
  app/src/main/java/com/nexos/reamobile/engine/AlfaJni.java \
  app/src/test/java/com/nexos/reamobile/engine/AlfaJniTest.java \
  app/src/main/java/com/nexos/reamobile/engine/AlfaUi.java \
  app/src/test/java/com/nexos/reamobile/engine/AlfaUiTest.java \
  app/src/main/java/com/nexos/reamobile/engine/AlfaCorr.java \
  app/src/test/java/com/nexos/reamobile/engine/AlfaCorrTest.java \
  docs/ALFA_1_NATIVO.md \
  docs/ALFA_2_UI.md \
  docs/ALFA_3_BLUEPRINT.md \
  app/src/main/java/com/nexos/reamobile/engine/ArscTable.java \
  app/src/test/java/com/nexos/reamobile/engine/ArscTableTest.java \
  docs/RECONSTRUCCION.md \
  app/src/main/java/com/nexos/reamobile/engine/Phantom.java \
  app/src/main/java/com/nexos/reamobile/engine/PhantomGroup.java \
  app/src/main/java/com/nexos/reamobile/engine/PhantomMetric.java \
  app/src/main/java/com/nexos/reamobile/engine/PhantomNet.java \
  app/src/main/java/com/nexos/reamobile/engine/PhantomUi.java \
  app/src/main/java/com/nexos/reamobile/engine/PhantomStore.java \
  app/src/main/java/com/nexos/reamobile/engine/PhantomData.java \
  app/src/main/java/com/nexos/reamobile/engine/PhantomJni.java \
  app/src/main/java/com/nexos/reamobile/engine/PhantomTaint.java \
  app/src/main/java/com/nexos/reamobile/engine/PhantomDecompile.java \
  app/src/main/java/com/nexos/reamobile/engine/PhantomNames.java \
  app/src/main/java/com/nexos/reamobile/engine/PhantomAttrib.java \
  app/src/test/java/com/nexos/reamobile/engine/PhantomJniTest.java \
  app/src/test/java/com/nexos/reamobile/engine/PhantomNetTest.java \
  app/src/test/java/com/nexos/reamobile/engine/PhantomUiTest.java \
  app/src/test/java/com/nexos/reamobile/engine/PhantomStoreTest.java \
  app/src/test/java/com/nexos/reamobile/engine/PhantomDataTest.java \
  app/src/test/java/com/nexos/reamobile/engine/PhantomGroupTest.java \
  app/src/test/java/com/nexos/reamobile/engine/PhantomMetricTest.java \
  app/src/test/java/com/nexos/reamobile/engine/PhantomTaintTest.java \
  app/src/test/java/com/nexos/reamobile/engine/PhantomPackTest.java \
  app/src/test/java/com/nexos/reamobile/engine/PhantomNamesTest.java \
  app/src/test/java/com/nexos/reamobile/engine/PhantomAttribTest.java \
  docs/PHANTOM.md \
  autopush.sh \
  app/src/main/java/com/nexos/reamobile/Session.kt \
  app/src/main/java/com/nexos/reamobile/CodeViewerActivity.kt \
  docs/FASE3_MOTOR_PROPIO.md \
  docs/FASE5_MATRIZ.md \
  .github/workflows/build-apk.yml \
  README.md
git commit -m "$MSG" || echo "Nada nuevo que commitear."
git push -u origin master
# Verificación final (Fase E): el push aterrizó y no queda nada fuera.
LOCAL=$(git rev-parse master)
REMOTE=$(git rev-parse origin/master)
if [ "$LOCAL" != "$REMOTE" ]; then
  echo "AVISO: master ($LOCAL) != origin/master ($REMOTE)"
  exit 1
fi
if [ -n "$(git status --porcelain)" ]; then
  echo "AVISO: quedan cambios sin commitear:"
  git status --porcelain
  exit 1
fi
echo "Push verificado: $LOCAL limpio y sincronizado."
