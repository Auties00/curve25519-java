package it.auties.curve25519.crypto;

public class ge_precomp {

    public int[] yplusx;
    public int[] yminusx;
    public int[] xy2d;

    public ge_precomp() {
        yplusx = new int[10];
        yminusx = new int[10];
        xy2d = new int[10];
    }

    public ge_precomp(int[] new_yplusx, int[] new_yminusx,
                      int[] new_xy2d) {
        yplusx = new_yplusx;
        yminusx = new_yminusx;
        xy2d = new_xy2d;
    }
}

