package com.liu233w.encryption.ex1;

import com.liu233w.encryption.ex1.exceptions.WrongInputException;
import org.junit.jupiter.api.Test;

import static com.google.common.truth.Truth.assertThat;

public class PlayfairCipherTest {

    private PlayfairCipher playfairCipher;

    public PlayfairCipherTest() throws WrongInputException {
        playfairCipher = new PlayfairCipher("INFOSEC");
    }

    @Test
    public void testConstructor() {
        char[][] table = playfairCipher.getTable();

        char[][] expected = {
                buildRowFromString("INFOS"),
                buildRowFromString("ECABD"),
                buildRowFromString("GHKLM"),
                buildRowFromString("PQRTU"),
                buildRowFromString("VWXYZ"),
        };

        assertThat(table).isEqualTo(expected);
    }

    private char[] buildRowFromString(String row) {
        char[] chars = new char[5];
        for (int i = 0; i < 5; ++i) {
            chars[i] = row.charAt(i);
        }
        return chars;
    }
}
