package com.liu233w.encryption.ex1;

import java.util.Optional;

/**
 * 用凯撒密码来对文本进行加密
 */
public class CaesarCipher {
    /**
     * 加密文本
     *
     * @param plaintext 要加密的文本（只能含有大写英文字母）
     * @param key       加密值（如果传入的key为当时加密时的值的相反数，为解密）
     * @return 传入值合格时为加密后的结果，否则为 None
     */
    public static Optional<String> encrypt(String plaintext, int key) {

        final StringBuilder ciphertext = new StringBuilder();

        for (int i = 0; i < plaintext.length(); ++i) {

            char c = plaintext.charAt(i);
            if (c < 65 || c > 90) {
                return Optional.empty();
            }

            c += key;
            if (c < 65) {
                c += 26;
            } else if (c > 90) {
                c -= 26;
            }

            ciphertext.append(c);
        }

        return Optional.of(ciphertext.toString());
    }
}
