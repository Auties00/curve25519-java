package it.auties.curve25519.crypto;

import java.util.Arrays;

public class sign_modified {

//CONVERT #include <string.h>
//CONVERT #include "crypto_sign.h"
//CONVERT #include "crypto_hash_sha512.h"
//CONVERT #include "ge.h"
//CONVERT #include "sc.h"
//CONVERT #include "zeroize.h"

    /* NEW: Compare to pristine crypto_sign()
       Uses explicit private key for nonce derivation and as scalar,
       instead of deriving both from a master key.
    */
    static int crypto_sign_modified(
            byte[] sm,
            byte[] m, long n,
            byte[] sk, byte[] pk,
            byte[] random
    ) {
        byte[] h = new byte[64];
        byte[] r = new byte[64];

        ge_p3 p = new ge_p3();
        if(random != null) {
            int count;

            /* NEW : add prefix to separate hash uses - see .h */
            sm[0] = (byte) 0xFE;
            for (count = 1; count < 32; count++)
                sm[count] = (byte) 0xFF;

            System.arraycopy(sk, 0, sm, 32, 32);
            System.arraycopy(m, 0, sm, 64, (int) n);

            /* NEW: add suffix of random data */
            System.arraycopy(random, 0, sm, (int) (n + 64), 64);

            Sha512.calculateDigest(r, sm, n + 128);
            return crypto_sign_modified(sm, n, sk, pk, h, r, p);
        }

        System.arraycopy(m, 0, sm, 64, (int) n);
        System.arraycopy(sk, 0, sm, 32, 32);

        Sha512.calculateDigest(r, Arrays.copyOfRange(sm, 32, sm.length), n + 32);
        return crypto_sign_modified(sm, n, sk, pk, h, r, p);
    }

    private static int crypto_sign_modified(byte[] sm, long n, byte[] sk, byte[] pk, byte[] h, byte[] r, ge_p3 p) {
        System.arraycopy(pk, 0, sm, 32, 32);
        sc_reduce.sc_reduce(r);
        ge_scalarmult_base.ge_scalarmult_base(p, r);
        ge_p3_tobytes.ge_p3_tobytes(sm, p);
        Sha512.calculateDigest(h, sm, n + 64);
        sc_reduce.sc_reduce(h);

        byte[] x = new byte[32];
        sc_muladd.sc_muladd(x, h, sk, r); /* NEW: Use privkey directly */
        System.arraycopy(x, 0, sm, 32, 32);
        return 0;
    }
}
