package encryption.bulletproof;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 极简 SHA-256 Sponge，用作 Fiat–Shamir Transcript
 */
public class Transcript {

    private static final String ALG = "SHA-256";
    private final ByteArrayOutputStream sponge = new ByteArrayOutputStream();

    public Transcript(byte[] domain) {
        try { sponge.write(domain); }
        catch (IOException e) { throw new RuntimeException(e); }
    }

    public void appendPoint(String label, byte[] pointBytes) {
        try {
            sponge.write(label.getBytes());
            sponge.write(pointBytes);
        } catch (IOException e) { throw new RuntimeException(e); }
    }

    public void appendScalar(String label, Scalar s) {
        try {
            sponge.write(label.getBytes());
            sponge.write(s.toBytes());
        } catch (IOException e) { throw new RuntimeException(e); }
    }

    /** 生成新挑战并把其哈希写回 transcript */
    public Scalar challengeScalar(String label) {
        try {
            MessageDigest md = MessageDigest.getInstance(ALG);
            md.update(sponge.toByteArray());
            md.update(label.getBytes());
            byte[] out = md.digest();

            // 链接熵以供后续使用
            sponge.write(label.getBytes());
            sponge.write(out);

            return new Scalar(new BigInteger(1, out));
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException(e);
        }
    }
}
