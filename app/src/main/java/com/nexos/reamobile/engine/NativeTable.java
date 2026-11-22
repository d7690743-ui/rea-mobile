package com.nexos.reamobile.engine;

/**
 * Clasificación de librerías nativas conocidas por nombre.
 * Java puro. Nunca lanza.
 */
public final class NativeTable {
    private NativeTable() {
    }

    private static final String[][] TABLE = {
            {"libllama", "LLM local (llama.cpp)"},
            {"libggml", "LLM local (ggml)"},
            {"libsd_jni", "difusión de imágenes (Stable Diffusion)"},
            {"liblitert", "inferencia ML (LiteRT)"},
            {"libtensorflowlite", "inferencia ML (TensorFlow Lite)"},
            {"libonnx", "inferencia ML (ONNX)"},
            {"libncnn", "inferencia ML (ncnn)"},
            {"libpytorch", "inferencia ML (PyTorch)"},
            {"libsnpe", "inferencia ML (Snapdragon SNPE)"},
            {"libflutter.so", "framework Flutter"},
            {"libapp.so", "código Dart compilado (Flutter AOT)"},
            {"libunity.so", "motor Unity"},
            {"libil2cpp.so", "Unity IL2CPP"},
            {"libreactnativejni", "framework React Native"},
            {"libfbjni", "React Native (fbjni)"},
            {"libhermes", "React Native (Hermes)"},
            {"libmonosgen", "Xamarin/.NET (Mono)"},
            {"libmono", "Xamarin/.NET (Mono)"},
            {"libxamarin", "Xamarin"},
            {"libsqlcipher", "base de datos cifrada (SQLCipher)"},
            {"librealm", "base de datos Realm"},
            {"libsqlite", "base de datos SQLite"},
            {"libffmpeg", "multimedia (FFmpeg)"},
            {"libavcodec", "multimedia (FFmpeg)"},
            {"libavformat", "multimedia (FFmpeg)"},
            {"libssl", "TLS (OpenSSL/BoringSSL)"},
            {"libcrypto", "cripto (OpenSSL)"},
            {"libsodium", "cripto (libsodium)"},
            {"libcurl", "red (curl)"},
            {"libtor", "red anónima (Tor)"},
            {"libfrida", "instrumentación (Frida)"},
            {"libxposed", "Xposed"},
            {"libdexhelper", "protector Bangcle"},
            {"libjiagu", "protector 360 Jiagu"},
            {"libtosprotection", "protector Tencent"},
            {"libapkprotect", "protector APKProtect"},
            {"libopencl", "GPU (OpenCL)"},
            {"libvulkan", "GPU (Vulkan)"},
            {"libomp.so", "runtime OpenMP"},
            {"libc++_shared", "STL C++"},
            {"libdatastore", "Jetpack DataStore"},
            {"libdartjni", "Dart JNI"},
    };

    /** Etiqueta para un nombre de entrada lib/, o null si no es conocida. Nunca lanza. */
    public static String classify(String entryName) {
        try {
            if (entryName == null) return null;
            String n = entryName.toLowerCase(java.util.Locale.US);
            for (String[] e : TABLE) {
                if (n.contains(e[0])) return e[1];
            }
        } catch (Throwable ignored) {
        }
        return null;
    }
}
