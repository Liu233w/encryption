package com.liu233w.encryption.ex1;

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
            throw new IllegalArgumentException("The length of the keyword cannot be bigger than 25");
        }

        boolean[] selected = new boolean[26];
        PlayfairCipherTableBuilder tableBuilder = new PlayfairCipherTableBuilder();

        for (int i = 0; i < keyword.length(); ++i) {

            int c = keyword.charAt(i);
            c -= 'A';

            if (c < 0 || c >= 26) {
                throw new IllegalArgumentException("The keyword can only contain upper alphabet");
            }
            if (selected[c]) {
                throw new IllegalArgumentException("There cannot be same alphabet in the keyword (Notice that I and J counts as the same letter)");
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

    /**
     * 获取加密Table（只用于调试）
     *
     * @return
     */
    public char[][] getTable() {
        return table;
    }

    public String displayTable() {

        final StringBuilder stringBuilder = new StringBuilder();

        for (int row = 0; row < table.length; row++) {
            for (int col = 0; col < table[row].length; col++) {
                stringBuilder.append(table[row][col]);
            }
            stringBuilder.append('\n');
        }

        return stringBuilder.toString();
    }

    /**
     * 加密文本
     *
     * @param plaintext
     * @return
     */
    public String encrypt(String plaintext) {
        plaintext = processText(plaintext);
        StringBuilder stringBuilder = new StringBuilder();

        for (int start = 0; start < plaintext.length(); start += 2) {
            String digram = plaintext.substring(start, start + 2);
            assert digram.length() == 2;

            stringBuilder.append(getPair(digram.charAt(0), digram.charAt(1)));
        }

        return stringBuilder.toString();
    }

    /**
     * 按照题目要求处理明文
     *
     * @param plainText
     * @return
     */
    private static String processText(String plainText) {

        final StringBuilder sb = new StringBuilder();

        if (plainText.charAt(0) < 'A' || plainText.charAt(0) > 'Z') {
            throw new IllegalArgumentException("The text must be upper alphabet");
        }
        sb.append(plainText.charAt(0));

        for (int i = 1; i < plainText.length(); i++) {

            if (plainText.charAt(i) < 'A' || plainText.charAt(i) > 'Z') {
                throw new IllegalArgumentException("The text must be upper alphabet");
            }
            if (plainText.charAt(i) == sb.charAt(sb.length() - 1)) {
                assert sb.charAt(sb.length() - 1) != 'X'; // 按照题目要求，如果是XX这样的字符的话，题目没有说怎么处理，这种情况下会无限循环
                sb.append('X');
                --i;
            } else {
                sb.append(plainText.charAt(i));
            }
        }
        if (sb.length() % 2 == 1) {
            sb.append('X');
        }
        return sb.toString();
    }

    /**
     * 获取某个分组的密文
     *
     * @param firstChar
     * @param secondChar
     * @return
     */
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
            /*
            12 -> AB

            1...A
            .....
            B...2

            or

            A...1
            .....
            2...B

            or

            B...2
            .....
            1...A

            or
            .........
             */
            return ""
                    + table[firstLocation.getRow()][secondLocation.getCol()]
                    + table[secondLocation.getRow()][firstLocation.getCol()];
        }
    }

    /**
     * 获取字母在字母表中的位置
     *
     * @param item
     * @return
     * @throws IllegalArgumentException
     */
    private Location getCharLocation(char item) {

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
