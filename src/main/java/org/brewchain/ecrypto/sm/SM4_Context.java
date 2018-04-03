package org.brewchain.ecrypto.sm;

/**
 * Email: king.camulos@gmail.com
 * Date: 2018/4/3
 * DESC:
 */
public class SM4_Context {
    public int mode;

    public long[] sk;

    public boolean isPadding;

    public SM4_Context()
    {
        this.mode = 1;
        this.isPadding = true;
        this.sk = new long[32];
    }
}
