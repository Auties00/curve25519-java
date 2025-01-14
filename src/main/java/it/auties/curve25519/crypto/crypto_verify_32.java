package it.auties.curve25519.crypto;

public class crypto_verify_32 {
    public static int crypto_verify_32(byte[] x, byte[] y) {
        int differentbits = 0;
        for (int count = 0; count < 32; count++) {
            differentbits |= (x[count] ^ y[count]);
        }
        return differentbits;
    }
}
