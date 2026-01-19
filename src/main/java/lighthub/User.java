package lighthub;

import encryption.MyECDSA;
import encryption.bulletproof.Scalar;

import java.security.KeyPair;

public class User {
    public final byte[] ecdsaPk;
    public final byte[] ecdsaSk;

    public Scalar value;

    public User(Scalar value) throws Exception {
        KeyPair keyPair = MyECDSA.generateKeyPair();
        byte[] privateKey = MyECDSA.getPrivateKeyBytes(keyPair);
        byte[] publicKey = MyECDSA.getCompressedPublicKey(keyPair);

        this.ecdsaPk = publicKey;
        this.ecdsaSk = privateKey;
        this.value = value;
    }
}
