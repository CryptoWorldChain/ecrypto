package org.brewchain.ecrypto.address.iota;

/**
 * Created by paul on 4/15/17.
 */
public class Pair<S, T> {
    public S low;
    public T hi;

    public Pair(S k, T v) {
        low = k;
        hi = v;
    }
}