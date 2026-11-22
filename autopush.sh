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
  app/src/main/java/com/nexos/reamobile/Session.kt \
  app/src/main/java/com/nexos/reamobile/CodeViewerActivity.kt \
  docs/FASE3_MOTOR_PROPIO.md \
  docs/FASE5_MATRIZ.md \
  .github/workflows/build-apk.yml \
  README.md
git commit -m "$MSG" || echo "Nada nuevo que commitear."
git push -u origin master
