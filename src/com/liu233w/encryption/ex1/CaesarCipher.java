package com.liu233w.encryption.ex1;

/**
 * 用凯撒密码来对文本进行加密
 */
public class CaesarCipher {
    /**
     * 加密文本
     *
     * @param plaintext 要加密的文本（只能含有大写英文字母）
     * @param key       加密值（如果传入的key为当时加密时的值的相反数，为解密）
     * @return 加密后的结果
     * @throws IllegalArgumentException 如果传入的值不合格，抛出此异常
     */
    public static String encrypt(String plaintext, int key) throws IllegalArgumentException {

        final StringBuilder ciphertext = new StringBuilder();

        for (int i = 0; i < plaintext.length(); ++i) {

            char c = plaintext.charAt(i);
            if (c < 'A' || c > 'Z') {
                throw new IllegalArgumentException("只能输入大写英文字母");
            }

            c += key;
            if (c < 'A') {
                c += 26;
            } else if (c > 'Z') {
                c -= 26;
            }

            ciphertext.append(c);
        }

        return ciphertext.toString();
    }
}
