package it.auties.curve25519.crypto;

public class ge_p3_0 {

//CONVERT #include "ge.h"

    public static void ge_p3_0(ge_p3 h) {
        fe_0.fe_0(h.X);
        fe_1.fe_1(h.Y);
        fe_1.fe_1(h.Z);
        fe_0.fe_0(h.T);
    }


}
