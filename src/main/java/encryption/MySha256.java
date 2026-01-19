package encryption;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.util.Arrays;

public class MySha256 {

    /**
     * 使用Bouncy Castle计算SHA-256并取前128位
     */
    public static BigInteger sha256First128BitsBC(byte[] input) {
        SHA256Digest digest = new SHA256Digest();
        byte[] fullHash = new byte[32]; // SHA-256是32字节

        digest.update(input, 0, input.length);
        digest.doFinal(fullHash, 0);

        // 取前16字节（128位）
        return new BigInteger(1, Arrays.copyOfRange(fullHash, 0, 16)) ;
    }

    /**
     * 使用流式API（适合大文件）
     */
    public static byte[] sha256First128BitsStreaming(byte[] input) {
        SHA256Digest digest = new SHA256Digest();
        byte[] fullHash = new byte[32];

        // 可以分批处理大数据
        digest.update(input, 0, input.length);
        digest.doFinal(fullHash, 0);

        return Arrays.copyOfRange(fullHash, 0, 16);
    }


}
