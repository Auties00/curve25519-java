package com.github.auties00.curve25519.crypto;

public class sc_isreduced {
    public static boolean sc_isreduced(byte[] s)
    {
        byte[] strict = new byte[64];

        System.arraycopy(s, 0, strict, 0, 32);
        sc_reduce.sc_reduce(strict);
        return crypto_verify_32.crypto_verify_32(strict, 0, s, 0) == 0;
    }

}
