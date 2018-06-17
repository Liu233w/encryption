package com.liu233w.encryption.ex2;

import com.liu233w.encryption.ex3.utils.DesCipher;
import com.liu233w.encryption.ex3.utils.DesKey;
import org.junit.jupiter.api.Test;

import static com.google.common.truth.Truth.assertThat;

public class DesCipherTest {

    @Test
    public void DesKey_CanBeGenerateRandomly() {
        final DesKey key1 = DesKey.random();
        assertThat(key1.getKey()).isNotEqualTo(0);

        final DesKey key2 = DesKey.random();
        assertThat(key1.getKey()).isNotEqualTo(key2.getKey());
    }

    @Test
    public void DesCipher_CanEncryptAndDecrypt() {
        final DesCipher desCipher = new DesCipher(DesKey.random());

        final String plaintext = "Hello World hhhhh";
        final byte[] ciphered = desCipher.encrypt(plaintext);

        assertThat(ciphered).isNotEmpty();

        final String decrypted = desCipher.decrypt(ciphered);

        assertThat(decrypted).isEqualTo(plaintext);
    }
}
