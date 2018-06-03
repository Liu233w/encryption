package com.liu233w.encryption.ex1;

import com.liu233w.encryption.ex1.exceptions.WrongInputException;

import java.util.HashSet;

/**
 * 实现了 Playfair 的加密算法
 */
public class PlayfairCipher {

    private char[][] table;

    /**
     * 使用指定的密钥初始化加密类
     *
     * @param keyword 密钥（参考题目要求）
     * @throws WrongInputException 密钥不合格时抛出
     */
    public PlayfairCipher(String keyword) throws WrongInputException {

        if (keyword.length() > 25) {
            throw new WrongInputException("密钥长度不能大于 25");
        }

        boolean[] selected = new boolean[26];
        PlayfairCipherTableBuilder tableBuilder = new PlayfairCipherTableBuilder();

        for (int i = 0; i < keyword.length(); ++i) {

            int c = keyword.charAt(i);
            c -= 'A';

            if (c < 0 || c >= 26) {
                throw new WrongInputException("密钥只能包含大写字母");
            }
            if (selected[c]) {
                throw new WrongInputException("密钥中的字母不能重复（注意密钥中I和J算同一个字母）");
            }

            // 单独处理 I J
            if (c == 'I' - 'A' || c == 'J' - 'A') {
                selected['I' - 'A'] = selected['J' - 'A'] = true;
                // 统一用 I 来表示 I/J
                tableBuilder.pushChar('I');
            } else {
                selected[c] = true;
                tableBuilder.pushChar((char) (c + 'A'));
            }
        }

        // 处理剩下的字符
        for (int c = 0; c < 26; ++c) {

            if (selected[c]) continue;

            if (c == 'I' - 'A' || c == 'J' - 'A') {
                selected['I' - 'A'] = selected['J' - 'A'] = true;
                tableBuilder.pushChar('I');
            } else {
                tableBuilder.pushChar((char) (c + 'A'));
            }
        }

        table = tableBuilder.getTable();
    }

    public char[][] getTable() {
        return table;
    }
}

/**
 * 用于构建加密表格
 */
class PlayfairCipherTableBuilder {

    private char[][] table;

    private int row;

    private int col;

    private final int SIZE = 5;

    public PlayfairCipherTableBuilder() {
        table = new char[SIZE][];
        for (int i = 0; i < SIZE; ++i) {
            table[i] = new char[SIZE];
        }
        row = 0;
        col = -1;
    }

    /**
     * 向加密表格中添加一个字符
     *
     * @param c
     * @return 能否继续添加（表格是否未满）
     */
    public boolean pushChar(char c) {
        if (++col >= SIZE) {
            ++row;
            col = 0;
        }
        table[row][col] = c;

        if (row == SIZE - 1 && col == SIZE - 1) {
            return false;
        } else {
            return true;
        }
    }

    /**
     * 获取加密表格
     *
     * @return
     */
    public char[][] getTable() {
        return table;
    }
}
