package accio.entity;

import java.math.BigInteger;
import java.security.KeyPair;

import accio.RSUC;
import encryption.MyECDSA;
import encryption.bulletproof.Scalar;

public class Hub {
    public final byte[] ecdsaPk;
    public final byte[] ecdsaSk;

    public Scalar value;

    public RSUC.KeyPair keyPair;

    public Hub(Scalar value) throws Exception {
        KeyPair keyPair = MyECDSA.generateKeyPair();
        byte[] privateKey = MyECDSA.getPrivateKeyBytes(keyPair);
        byte[] publicKey = MyECDSA.getCompressedPublicKey(keyPair);

        this.ecdsaPk = publicKey;
        this.ecdsaSk = privateKey;
        this.value = value;
    }

    public void setKeyPair(RSUC.KeyPair keyPair) {
        this.keyPair = keyPair;
    }
}
