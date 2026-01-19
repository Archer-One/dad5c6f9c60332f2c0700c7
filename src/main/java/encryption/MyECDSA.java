package encryption;

import org.bouncycastle.asn1.*;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

public class MyECDSA {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String CURVE_NAME = "secp256k1";
    private static final ECNamedCurveParameterSpec EC_SPEC =
            ECNamedCurveTable.getParameterSpec(CURVE_NAME);
    private static final ECDomainParameters EC_PARAMS = new ECDomainParameters(
            EC_SPEC.getCurve(), EC_SPEC.getG(), EC_SPEC.getN(), EC_SPEC.getH());

    /**
     * 生成密钥对（Java标准API）
     */
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
        keyGen.initialize(new ECGenParameterSpec(CURVE_NAME));
        return keyGen.generateKeyPair();
    }

    /**
     * 签名
     */
    public static byte[] sign(byte[] privateKey, byte[] message) {
        try {
            ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));

            ECPrivateKeyParameters privKeyParams = new ECPrivateKeyParameters(
                    new BigInteger(1, privateKey), EC_PARAMS);
            signer.init(true, privKeyParams);

            byte[] hash = sha256(message);
            BigInteger[] signature = signer.generateSignature(hash);

            BigInteger r = signature[0];
            BigInteger s = signature[1];

            // 规范化s值
            BigInteger halfN = EC_PARAMS.getN().shiftRight(1);
            if (s.compareTo(halfN) > 0) {
                s = EC_PARAMS.getN().subtract(s);
            }

            return encodeDER(r, s);

        } catch (Exception e) {
            throw new RuntimeException("签名失败", e);
        }
    }

    /**
     * 验证签名
     */
    public static boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
        try {
            ECDSASigner verifier = new ECDSASigner();

            ECPoint pubKeyPoint = EC_PARAMS.getCurve().decodePoint(publicKey);
            ECPublicKeyParameters pubKeyParams = new ECPublicKeyParameters(
                    pubKeyPoint, EC_PARAMS);
            verifier.init(false, pubKeyParams);

            BigInteger[] sig = decodeDER(signature);
            if (sig == null) return false;

            byte[] hash = sha256(message);
            return verifier.verifySignature(hash, sig[0], sig[1]);

        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 从KeyPair获取私钥字节
     */
    public static byte[] getPrivateKeyBytes(KeyPair keyPair) throws Exception {
        // 使用BC的转换工具
        ECPrivateKeyParameters privParams = (ECPrivateKeyParameters)
                org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil
                        .generatePrivateKeyParameter(keyPair.getPrivate());
        BigInteger d = privParams.getD();
        return toBytesPadded(d, 32);
    }

    /**
     * 从KeyPair获取压缩公钥
     */
    public static byte[] getCompressedPublicKey(KeyPair keyPair) throws Exception {
        ECPublicKeyParameters pubParams = (ECPublicKeyParameters)
                org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil
                        .generatePublicKeyParameter(keyPair.getPublic());
        return pubParams.getQ().getEncoded(true);
    }

    // 辅助方法保持不变
    private static byte[] sha256(byte[] message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(message);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] encodeDER(BigInteger r, BigInteger s) {
        try {
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1Integer(r));
            v.add(new ASN1Integer(s));
            return new DERSequence(v).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("DER编码失败", e);
        }
    }

    private static BigInteger[] decodeDER(byte[] signature) {
        try {
            ASN1Sequence seq = ASN1Sequence.getInstance(signature);
            if (seq.size() != 2) return null;

            BigInteger r = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
            BigInteger s = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();

            return new BigInteger[]{r, s};
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] toBytesPadded(BigInteger value, int length) {
        byte[] result = new byte[length];
        byte[] bytes = value.toByteArray();

        int start = (bytes[0] == 0) ? 1 : 0;
        int copyLength = bytes.length - start;

        if (copyLength > length) {
            throw new IllegalArgumentException("值太大，无法填充到指定长度");
        }

        System.arraycopy(bytes, start, result, length - copyLength, copyLength);
        return result;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("=== 测试 ===");

        KeyPair keyPair = generateKeyPair();
        byte[] privateKey = getPrivateKeyBytes(keyPair);
        byte[] publicKey = getCompressedPublicKey(keyPair);


        String message = "测试消息";
        byte[] signature = sign(privateKey, message.getBytes());

        System.out.println("签名: " + Hex.toHexString(signature));
        System.out.println("验证: " + verify(publicKey, message.getBytes(), signature));
    }
}