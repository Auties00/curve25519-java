package com.github.auties00.curve25519.crypto;

public class point_isreduced {
    public static boolean point_isreduced(byte[] p)
    {
        byte[] strict = new byte[32];

        System.arraycopy(p, 0, strict, 0, 32);
        strict[31] &= 0x7F; /* mask off sign bit */
        return fe_isreduced.fe_isreduced(strict, 0);
    }

}
