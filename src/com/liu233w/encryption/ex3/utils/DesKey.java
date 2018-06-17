package com.liu233w.encryption.ex3.utils;

import java.util.Random;

public class DesKey {
    private long key;

    public DesKey(long key) {
        this.key = key;
    }

    public long getKey() {
        return key;
    }

    /**
     * Generate random des key
     *
     * @return
     */
    public static DesKey random() {
        return new DesKey(new Random().nextLong());
    }
}
