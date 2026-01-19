package lighthub;

import accio.RSUC;
import encryption.MyECDSA;
import encryption.bulletproof.Scalar;

import java.security.KeyPair;

public class Hub {
    public final byte[] ecdsaPk;
    public final byte[] ecdsaSk;

    public Scalar value;

    public RDBS.KeyPair keyPair;

    public Hub(Scalar value) throws Exception {
        KeyPair keyPair = MyECDSA.generateKeyPair();
        byte[] privateKey = MyECDSA.getPrivateKeyBytes(keyPair);
        byte[] publicKey = MyECDSA.getCompressedPublicKey(keyPair);

        this.ecdsaPk = publicKey;
        this.ecdsaSk = privateKey;
        this.value = value;
    }

    public void setKeyPair(RDBS.KeyPair keyPair) {
        this.keyPair = keyPair;
    }
}
