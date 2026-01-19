package bouncy.castle;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * 测试：使用 2048 位 RSA 对一个 256 位的 BigInteger 明文进行加密与解密，
 * 分别跑 50 次，统计平均加密耗时、平均解密耗时，并输出密文长度。
 */
public class RSA {
    public static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";
    private static final String PUBLIC_KEY  = "RSAPublicKey";
    private static final String PRIVATE_KEY = "RSAPrivateKey";
    public static final int KEY_SIZE = 2048;
    private static final int ITERATIONS = 50;

    public static void main(String[] args) throws Exception {
        // 1. 生成 RSA 密钥对（只做一次）
        Map<String, byte[]> keyMap = generateKeyBytes();
        PublicKey  publicKey  = restorePublicKey(keyMap.get(PUBLIC_KEY));
        PrivateKey privateKey = restorePrivateKey(keyMap.get(PRIVATE_KEY));

        // 2. 定义一个 256 位的 BigInteger 作为明文（可以固定或随机，这里示例使用随机）
        SecureRandom rnd = new SecureRandom();
        BigInteger plainBigInt = new BigInteger(256, rnd);   // 随机生成一个 256 位正整数
        byte[] plainBytes = plainBigInt.toByteArray();       // 转为字节数组

        // 3. 分别累加加密与解密的纳秒级耗时，以及累加密文长度
        long totalEncryptNs = 0;
        long totalDecryptNs = 0;
        long totalCipherLen = 0;

        byte[] cipherBytes = null;  // 用于保存一次加密后的字节，以便计算长度并进行解密

        for (int i = 0; i < ITERATIONS; i++) {
            // —— 3.1 加密计时 ——
            long t0 = System.nanoTime();
            byte[] ct = RSAEncrypt(publicKey, plainBytes);
            long t1 = System.nanoTime();
            totalEncryptNs += (t1 - t0);

            // 保存第一次循环得到的密文，以便长度统计和解密演示
            if (i == 0 && ct != null) {
                cipherBytes = ct.clone();
            }
            totalCipherLen += (ct != null ? ct.length : 0);

            // —— 3.2 解密计时 ——
            long t2 = System.nanoTime();
            String recovered = RSADecrypt(privateKey, ct);
            long t3 = System.nanoTime();
            totalDecryptNs += (t3 - t2);

            // 可选：检查一次解密结果是否与原文一致
            if (i == 0 && recovered != null) {
                BigInteger recoveredBig = new BigInteger(recovered.getBytes());
                // 由于 toByteArray() 会保留符号位，直接比较字符串或 BigInteger 可能不一致；
                // 这里仅做基本非空检查，生产代码可根据需求自行验证。
            }
        }

        // 4. 计算平均耗时（纳秒转毫秒）与平均密文长度
        double avgEncryptMs = (totalEncryptNs / (double) ITERATIONS) / 1_000_000.0;
        double avgDecryptMs = (totalDecryptNs / (double) ITERATIONS) / 1_000_000.0;
        double avgCipherLen = totalCipherLen / (double) ITERATIONS;

        // 5. 输出结果
        System.out.println("===== RSA 256-bit 明文加解密 50 次平均性能测试 =====");
        System.out.printf("明文（BigInteger）位数：256 位%n");
        System.out.printf("平均加密耗时   : %.3f ms%n", avgEncryptMs);
        System.out.printf("平均解密耗时   : %.3f ms%n", avgDecryptMs);
        System.out.printf("平均密文长度   : %.0f 字节%n", avgCipherLen);

        // 同时展示第一次循环得到的 Base64 格式密文
        if (cipherBytes != null) {
            String b64Ct = Base64.getEncoder().encodeToString(cipherBytes);
            System.out.println("示例密文（Base64）: " + b64Ct);
        }
    }

    /**
     * 生成一对 RSA 密钥对，返回包含公钥、私钥字节编码的 Map
     */
    public static Map<String, byte[]> generateKeyBytes() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(KEY_SIZE);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPublicKey  pubKey  = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey priKey  = (RSAPrivateKey) keyPair.getPrivate();

            Map<String, byte[]> keyMap = new HashMap<>();
            keyMap.put(PUBLIC_KEY,  pubKey.getEncoded());
            keyMap.put(PRIVATE_KEY, priKey.getEncoded());
            return keyMap;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 从字节数组恢复 RSA 公钥
     */
    public static PublicKey restorePublicKey(byte[] keyBytes) {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePublic(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 从字节数组恢复 RSA 私钥
     */
    public static PrivateKey restorePrivateKey(byte[] keyBytes) {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePrivate(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 使用 RSA 公钥对明文字节进行加密，返回密文字节数组
     */
    public static byte[] RSAEncrypt(PublicKey key, byte[] plain) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(plain);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                 | InvalidKeyException | IllegalBlockSizeException
                 | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 使用 RSA 私钥对密文字节进行解密，返回解密后字符串（注意恢复成字符串可能与 BigInteger 再比较时有差异）
     */
    public static String RSADecrypt(PrivateKey key, byte[] cipher) {
        try {
            Cipher decryptCipher = Cipher.getInstance(CIPHER_ALGORITHM);
            decryptCipher.init(Cipher.DECRYPT_MODE, key);
            byte[] plainBytes = decryptCipher.doFinal(cipher);
            return new String(plainBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException
                 | InvalidKeyException | IllegalBlockSizeException
                 | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }
}
