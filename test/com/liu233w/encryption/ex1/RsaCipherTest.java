package com.liu233w.encryption.ex1;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static com.google.common.truth.Truth.assertThat;

public class RsaCipherTest {

    @Test
    public void testEncryptAndDecrypt() {
        final RsaKeyPair rsaKeyPair = new RsaKeyPair(BigInteger.valueOf(3 * 11), BigInteger.valueOf(3), BigInteger.valueOf(7));

        assertThat(RsaCipher.encrypt(BigInteger.valueOf(24), rsaKeyPair.getPublicKey()))
                .isEqualTo(BigInteger.valueOf(30));

        assertThat(RsaCipher.decrypt(BigInteger.valueOf(30), rsaKeyPair.getPrivateKey()))
                .isEqualTo(BigInteger.valueOf(24));
    }
}
