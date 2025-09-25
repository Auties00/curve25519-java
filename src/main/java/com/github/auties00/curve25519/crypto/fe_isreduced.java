package com.github.auties00.curve25519.crypto;

public class fe_isreduced {
    public static boolean fe_isreduced(byte[] s, int offset)
    {
        int[] f = new int[10];
        byte[] strict = new byte[32];

        fe_frombytes.fe_frombytes(f, s, offset);
        fe_tobytes.fe_tobytes(strict, 0, f);
        return crypto_verify_32.crypto_verify_32(strict, 0, s, offset) == 0;
    }

}
