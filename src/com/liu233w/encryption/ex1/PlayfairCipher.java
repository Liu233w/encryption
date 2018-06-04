package com.liu233w.encryption.ex1;

import com.liu233w.encryption.utils.Pair;

import java.util.Objects;

/**
 * 实现了 Playfair 的加密算法
 */
public class PlayfairCipher {

    public static final int TABLE_SIZE = 5;
    private char[][] table;

    /**
     * 使用指定的密钥初始化加密类
     *
     * @param keyword 密钥（参考题目要求）
     * @throws IllegalArgumentException 密钥不合格时抛出
     */
    public PlayfairCipher(String keyword) throws IllegalArgumentException {

        if (keyword.length() > 25) {
            throw new IllegalArgumentException("密钥长度不能大于 25");
        }

        boolean[] selected = new boolean[26];
        PlayfairCipherTableBuilder tableBuilder = new PlayfairCipherTableBuilder();

        for (int i = 0; i < keyword.length(); ++i) {

            int c = keyword.charAt(i);
            c -= 'A';

            if (c < 0 || c >= 26) {
                throw new IllegalArgumentException("密钥只能包含大写字母");
            }
            if (selected[c]) {
                throw new IllegalArgumentException("密钥中的字母不能重复（注意密钥中I和J算同一个字母）");
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

    public String encrypt(String plaintext) {
        StringBuilder stringBuilder = new StringBuilder();
        String[] digrams = plaintext.split(".*", 2);

        for (String digram :
                digrams) {
            assert digram.length() == 1 || digram.length() == 2;
            if (digram.length() == 1) {
                stringBuilder.append(digram);
                stringBuilder.append('X');
            } else {
                stringBuilder.append(getPair(digram.charAt(0), digram.charAt(1)));
            }
        }

        return stringBuilder.toString();
    }

    private String getPair(char firstChar, char secondChar) {

        if (firstChar == secondChar) {
            return "" + firstChar + 'X';
        }

        Location firstLocation = getCharLocation(firstChar);
        Location secondLocation = getCharLocation(secondChar);

        if (firstLocation.getRow() == secondLocation.getRow()) {
            // 在同一行
            return ""
                    + table[firstLocation.getRow()][(firstLocation.getCol() + 1) % TABLE_SIZE]
                    + table[secondLocation.getRow()][(secondLocation.getCol() + 1) % TABLE_SIZE];

        } else if (firstLocation.getCol() == secondLocation.getCol()) {
            // 同一列
            return ""
                    + table[(firstLocation.getRow() + 1) % TABLE_SIZE][firstLocation.getCol()]
                    + table[(secondLocation.getRow() + 1) % TABLE_SIZE][secondLocation.getCol()];

        } else {
            // 让行号小的在前面
            if (firstLocation.getRow() > secondLocation.getRow()) {
                final Location temp = firstLocation;
                firstLocation = secondLocation;
                secondLocation = temp;
            }

            /*
            1....
            .....
            ....2

            or

            ....1
            .....
            2....
             */
            return ""
                    + table[firstLocation.getRow()][secondLocation.getCol()]
                    + table[secondLocation.getRow()][firstLocation.getCol()];
        }
    }

    private Location getCharLocation(char item) throws IllegalArgumentException {

        if (item < 'A' || item > 'Z') {
            throw new IllegalArgumentException("要加密的文字必须是大写的英文字母");
        }

        if (item == 'J') {
            item = 'I';
        }

        for (int row = 0; row < TABLE_SIZE; ++row) {
            for (int col = 0; col < TABLE_SIZE; ++col) {
                if (table[row][col] == item) {
                    return new Location(row, col);
                }
            }
        }

        throw new AssertionError("至少应该找到一个字符");
    }
}

/**
 * 用于构建加密表格
 */
class PlayfairCipherTableBuilder {

    private char[][] table;

    private int row;

    private int col;

    private static final int SIZE = 5;

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

/**
 * 表示表格中的一个位置
 */
class Location {
    private int row;
    private int col;

    public Location(int row, int col) {
        this.row = row;
        this.col = col;
    }

    public int getRow() {
        return row;
    }

    public void setRow(int row) {
        this.row = row;
    }

    public int getCol() {
        return col;
    }

    public void setCol(int col) {
        this.col = col;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Location location = (Location) o;
        return row == location.row &&
                col == location.col;
    }

    @Override
    public int hashCode() {
        return Objects.hash(row, col);
    }
}
