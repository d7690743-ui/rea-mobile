package com.nexos.reamobile

import org.junit.Assert.assertTrue
import org.junit.Test

/** P1-4: el LRU de sesión recorta por caracteres además de por entradas. */
class SessionCacheTest {

    @Test
    fun recortaPorCaracteres() {
        Session.resetCache()
        try {
            val big = "x".repeat(6_000_000)
            Session.putSmali("a", big)
            Session.putSmali("b", big)
            Session.putSmali("c", big)
            Session.putSmali("d", big)
            assertTrue(Session.smaliCache["a"] == null)
            assertTrue(Session.smaliCache["d"] != null)
            var total = 0
            for (v in Session.smaliSnapshot().values) total += v.length
            assertTrue("total=$total", total <= Session.MAX_CACHE_CHARS)
        } finally {
            Session.resetCache()
        }
    }

    @Test
    fun respetaTopeEntradas() {
        Session.resetCache()
        try {
            for (i in 0 until Session.MAX_CACHE_CLASSES + 50) {
                Session.putSmali("k$i", "v")
            }
            assertTrue(Session.smaliCache.size <= Session.MAX_CACHE_CLASSES)
        } finally {
            Session.resetCache()
        }
    }
}
