package com.liu233w.encryption.ex1;

import org.junit.jupiter.api.Test;

import static com.google.common.truth.Truth.assertThat;

public class PlayfairCipherTest {

    private PlayfairCipher playfairCipher;

    public PlayfairCipherTest() throws IllegalArgumentException {
        playfairCipher = new PlayfairCipher("INFOSEC");
    }

    @Test
    public void testConstructor() throws IllegalArgumentException {
        char[][] table = playfairCipher.getTable();

        char[][] expected = {
                buildRowFromString("INFOS"),
                buildRowFromString("ECABD"),
                buildRowFromString("GHKLM"),
                buildRowFromString("PQRTU"),
                buildRowFromString("VWXYZ"),
        };

        assertThat(table).isEqualTo(expected);

        assertThat(new PlayfairCipher("NFOSEC").getTable())
                .isEqualTo(new char[][]{
                        buildRowFromString("NFOSE"),
                        buildRowFromString("CABDG"),
                        buildRowFromString("HIKLM"),
                        buildRowFromString("PQRTU"),
                        buildRowFromString("VWXYZ"),
                });
    }

    private char[] buildRowFromString(String row) {
        char[] chars = new char[5];
        for (int i = 0; i < 5; ++i) {
            chars[i] = row.charAt(i);
        }
        return chars;
    }

    @Test
    public void testEncrypt() {
        doTest("CRYPTOISTOOEASY", "AQVTYBNIYBYFCBOZ");
        doTest("CRYPTOISTOOEAS", "AQVTYBNIYBYFCBFZ");
    }

    private void doTest(String plaintext, String cipherText) {
        assertThat(playfairCipher.encrypt(plaintext)).isEqualTo(cipherText);
    }
}
