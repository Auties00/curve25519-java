package com.github.auties00.curve25519.crypto;

public class crypto_verify_32 {
    public static int crypto_verify_32(byte[] x, int x_off, byte[] y, int y_off) {
        int differentbits = 0;
        for (int count = 0; count < 32; count++) {
            differentbits |= (x[x_off + count] ^ y[y_off + count]);
        }
        return differentbits;
    }
}
