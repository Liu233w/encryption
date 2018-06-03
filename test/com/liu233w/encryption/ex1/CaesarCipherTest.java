package com.liu233w.encryption.ex1;

import com.liu233w.encryption.ex1.exceptions.WrongInputException;
import org.junit.jupiter.api.Test;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class CaesarCipherTest {

    @Test
    public void testEncrypt() throws WrongInputException {
        doTest("HELLO", 3, "KHOOR");
        doTest("ZZZ", 3, "CCC");
        doTest("KHOOR", -3, "HELLO");
        doTest("CCC", -3, "ZZZ");
    }

    private void doTest(String input, int key, String expected) throws WrongInputException {
        assertThat(CaesarCipher.encrypt(input, key)).isEqualTo(expected);
    }

    @Test
    public void testError() {
        doTestError("a");
        doTestError("AS IF");
        doTestError(",");
    }

    public void doTestError(String input) {
        assertThrows(
                WrongInputException.class,
                () -> CaesarCipher.encrypt(input, 3),
                "只能输入大写英文字母"
        );
    }
}
