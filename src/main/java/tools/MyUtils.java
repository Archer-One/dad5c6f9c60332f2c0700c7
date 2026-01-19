package tools;


import encryption.RSAEncryption;
import encryption.RandomLetter;
import global.Global;
import org.aion.tetryon.*;


import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.util.HashMap;
import java.util.Properties;
import java.util.logging.Logger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
public class MyUtils {
    int messageLenMax = 1024;
    String configFile;

    public static void sendMessage(Socket sender, byte[] message) {
        try {
            DataOutputStream dout = new DataOutputStream(sender.getOutputStream());
            dout.writeInt(message.length);

            dout.write(message);
            dout.flush();
        } catch (IOException e) {
            System.out.println("Send message error!");
        }
    }

    public static byte[] intToBitBigEndian(BigInteger value, int bitLength) {
        // 验证bit长度是8的倍数
        if (bitLength % 8 != 0) {
            throw new IllegalArgumentException("bitLength必须是8的倍数");
        }

        int byteLength = bitLength / 8;

        // 获取BigInteger的字节数组（大端序）
        byte[] bigIntBytes = value.toByteArray();

        // 如果BigInteger的字节长度大于目标长度，需要截断
        if (bigIntBytes.length > byteLength) {
            // 取最后byteLength个字节（因为BigInteger的toByteArray包含符号位）
            return Arrays.copyOfRange(bigIntBytes, bigIntBytes.length - byteLength, bigIntBytes.length);
        }
        // 如果小于目标长度，需要高位补0
        else if (bigIntBytes.length < byteLength) {
            byte[] result = new byte[byteLength];
            // 计算需要填充的字节数
            int padding = byteLength - bigIntBytes.length;
            // 将bigIntBytes复制到result的末尾（大端序高位在前，所以从前面开始填充0）
            System.arraycopy(bigIntBytes, 0, result, padding, bigIntBytes.length);
            // 前面的字节自动为0（Java数组初始化全0）
            return result;
        }
        // 长度正好相等
        else {
            return bigIntBytes;
        }
    }

    /**
     * 使用ByteBuffer的版本（适用于int/long/short）
     * @param value 长整型值
     * @param bitLength 期望的bit长度（必须是8的倍数）
     * @return 指定长度的字节数组
     */
    public static byte[] longToBitBigEndian(long value, int bitLength) {
        if (bitLength % 8 != 0) {
            throw new IllegalArgumentException("bitLength必须是8的倍数");
        }

        int byteLength = bitLength / 8;
        ByteBuffer buffer = ByteBuffer.allocate(byteLength);
        buffer.order(ByteOrder.BIG_ENDIAN);

        // 根据字节长度选择合适的方法
        switch (byteLength) {
            case 1:
                buffer.put((byte) value);
                break;
            case 2:
                buffer.putShort((short) value);
                break;
            case 4:
                buffer.putInt((int) value);
                break;
            case 8:
                buffer.putLong(value);
                break;
            default:
                // 对于其他长度，使用BigInteger
                BigInteger bigInt = BigInteger.valueOf(value);
                byte[] bytes = bigInt.toByteArray();
                if (bytes.length > byteLength) {
                    bytes = Arrays.copyOfRange(bytes, bytes.length - byteLength, bytes.length);
                }
                buffer.put(bytes);
                // 需要填充高位0
                while (buffer.position() < byteLength) {
                    buffer.put((byte) 0);
                }
        }

        return buffer.array();
    }

    /**
     * 优化的BigInteger转换（处理符号位）
     */
    public static byte[] bigIntegerToFixedBytes(BigInteger value, int byteLength) {
        byte[] result = new byte[byteLength];
        byte[] valueBytes = value.toByteArray();

        int srcPos = 0;
        int destPos = byteLength - valueBytes.length;

        // 如果valueBytes有额外的符号位字节（当值为正但最高位为1时）
        if (valueBytes.length > byteLength ||
                (valueBytes.length == byteLength + 1 && valueBytes[0] == 0)) {
            // 去除可能的前导0字节
            if (valueBytes[0] == 0) {
                srcPos = 1;
                destPos = byteLength - (valueBytes.length - 1);
            } else {
                // 如果value太大，截取最后byteLength个字节
                srcPos = valueBytes.length - byteLength;
                destPos = 0;
            }
        }

        // 计算要复制的长度
        int length = Math.min(valueBytes.length - srcPos, byteLength - destPos);
        System.arraycopy(valueBytes, srcPos, result, destPos, length);

        return result;
    }



}
