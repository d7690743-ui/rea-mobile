package com.nexos.reamobile.engine;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** Pruebas de reglas de secretos de alta confianza y entropía. */
public class SecretRulesTest {

    @Test
    public void formatosConocidos() {
        assertTrue(SecretRules.match("AKIAIOSFODNN7EXAMPLE").contains("aws-access"));
        assertTrue(SecretRules.match("AIza12345678901234567890123456789012345").contains("google-api"));
        assertTrue(SecretRules.match("ghp_abcdefghij1234567890").contains("github"));
        assertTrue(SecretRules.match("xoxb-1234-abcd").contains("slack-token"));
        assertTrue(SecretRules.match("sk-live-abc123XYZ").contains("stripe"));
        assertTrue(SecretRules.match("-----BEGIN RSA PRIVATE KEY-----").contains("private-key"));
        assertTrue(SecretRules.match("password=\"s3cret!\"").contains("asignacion"));
        assertTrue(SecretRules.match("api_key = \"abc123\"").contains("asignacion"));
    }

    @Test
    public void ruidoNoCasa() {
        assertTrue(SecretRules.match("token").isEmpty());
        assertTrue(SecretRules.match("password").isEmpty());
        assertTrue(SecretRules.match("api key").isEmpty());
        assertTrue(SecretRules.match("hello world").isEmpty());
        assertTrue(SecretRules.match("").isEmpty());
        assertTrue(SecretRules.match(null).isEmpty());
        assertTrue(SecretRules.match("String token = name;").isEmpty());
    }

    @Test
    public void shannonOrdena() {
        double baja = SecretRules.shannon("aaaaaaaaaaaaaaaaaaaaaaaa");
        double alta = SecretRules.shannon("7J3k9Q2mZ8vX4pL6sN1bV0cR");
        assertTrue("baja=" + baja, baja < 1.0);
        assertTrue("alta=" + alta, alta > 4.0);
        assertTrue(SecretRules.shannon(null) == 0);
    }

    @Test
    public void tokenOpaco() {
        assertTrue(SecretRules.isTokenLike("7J3k9Q2mZ8vX4pL6sN1bV0cR5tYw"));
        assertFalse(SecretRules.isTokenLike("https://api.ejemplo.com/v1/player"));
        assertFalse(SecretRules.isTokenLike("hello"));
        assertFalse(SecretRules.isTokenLike("aaaaaaaaaaaaaaaaaaaaaaaa"));
        assertFalse(SecretRules.isTokenLike("Lcom/google/firebase/Messaging;"));
        assertFalse(SecretRules.isTokenLike("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"));
        assertFalse(SecretRules.isTokenLike("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"));
        assertFalse(SecretRules.isTokenLike("0123456789ABCDEF0123456789ABCDEF"));
        assertFalse(SecretRules.isTokenLike(
                "//www.gstatic.com/youtube/media/ytm/images/ytu_promo_dialog_dreads_phone_1248x264.jpg"));
        assertTrue(SecretRules.isTokenLike("7J3k9Q2mZ8vX4pL6/sN1bV0cR5tYw"));
        assertFalse(SecretRules.isTokenLike(null));
    }

    @Test
    public void entropiaEnLinea() {
        assertTrue(SecretRules.hasEntropyToken("String k = \"7J3k9Q2mZ8vX4pL6sN1bV0cR5tYw\";"));
        assertFalse(SecretRules.hasEntropyToken("String u = \"https://api.ejemplo.com/v1/player\";"));
        assertFalse(SecretRules.hasEntropyToken("String token = name;"));
        assertFalse(SecretRules.hasEntropyToken(null));
    }
}
