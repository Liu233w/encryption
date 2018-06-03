package com.liu233w.encryption.ex1;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CaesarCipherTest {

    @Test
    public void testEncrypt() {
        doTest("HELLO", 3, "KHOOR");
        doTest("ZZZ", 3, "CCC");
        doTest("KHOOR", -3, "HELLO");
        doTest("CCC", -3, "ZZZ");
    }

    private void doTest(String input, int key, String expected) {
        Optional<String> result = CaesarCipher.encrypt(input, key);
        assertEquals(result, Optional.of(expected));
    }

    @Test
    public void testError() {
        doTestError("a");
        doTestError("AS IF");
        doTestError(",");
    }

    public void doTestError(String input) {
        Optional<String> result = CaesarCipher.encrypt(input, 3);
        assertEquals(result, Optional.empty());
    }
}
