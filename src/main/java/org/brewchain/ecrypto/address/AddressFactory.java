package org.brewchain.ecrypto.address;

/**
 * Created by paul on 7/27/17.
 */
public abstract class AddressFactory {
    public static NewAddress create(Mode mode) {
        switch (mode) {
            case IOTA:
                return new IoTANewAddress();
            default:
                return null;
        }
    }

    public enum Mode {
    		IOTA
    		//,ETH
        //,BTH
    }
}