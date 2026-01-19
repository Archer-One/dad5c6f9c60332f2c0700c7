package org.aion.tetryon;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
/**
 * A collection of Elliptic Curve operations on G1 for alt_bn128. This implementation is
 * heavily based on the EC API exposed by the AVM.
 *
 * <p>
 * Curve definition: y^2 = x^3 + b
 * <p>
 */
public class G1 {

    // The prime q in the base field F_q for G1
    private static final BigInteger q = new BigInteger("21888242871839275222246405745257275088696311157297823662689037894645226208583");

    public static BigInteger getQ() {
        return q;
    }
    public static G1Point negate(G1Point p) {
        if (p.isZero()) {
            return new G1Point(Fp.zero(), Fp.zero());
        }
        return new G1Point(p.x, new Fp(q.subtract(p.y.c0.mod(q))));
    }

    public static G1Point add(G1Point p1, G1Point p2) throws Exception {
        byte[] p1data = Util.serializeG1(p1);
        byte[] p2data = Util.serializeG1(p2);
        byte[] resultData = AltBn128.g1EcAdd(p1data, p2data);
        G1Point result = Util.deserializeG1(resultData);
        return result;
    }

    public static G1Point mul(G1Point p, BigInteger s) throws Exception {
        byte[] pdata = Util.serializeG1(p);
        byte[] resultData = AltBn128.g1EcMul(pdata, s);
        G1Point result = Util.deserializeG1(resultData);
        return result;
    }


    public static byte[] concatenate(BigInteger num, String address) {//用于拼接地址
        // 将 BigInteger 转换为 byte 数组
        byte[] numBytes = num.toByteArray();

        // 将 String 转换为 byte 数组
        byte[] addressBytes = address.getBytes();

        // 创建一个新的数组来存储拼接结果
        byte[] concatenatedArray = new byte[numBytes.length + addressBytes.length];

        // 复制 numBytes 到 concatenatedArray 的开头
        System.arraycopy(numBytes, 0, concatenatedArray, 0, numBytes.length);

        // 复制 addressBytes 到 concatenatedArray 的后续位置
        System.arraycopy(addressBytes, 0, concatenatedArray, numBytes.length, addressBytes.length);

        return concatenatedArray;
    }

    public static G1Point HashToG1(BigInteger num ,String address) throws Exception {

        // 将 BigInteger 转换成字节数组
        byte[] bytes = concatenate(num,address);
        BigInteger modResult = new BigInteger("0");
        // 使用 SHA-256 对字节数组进行哈希
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(bytes);

            // 将哈希结果转换回 BigInteger
            BigInteger hashBigInt = new BigInteger(1, hashBytes);

            // 对结果进行模运算，使其落在大素数内
            modResult = hashBigInt.mod(q);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] resultData = AltBn128.HashToG1(modResult);
        G1Point result = Util.deserializeG1(resultData);
        return result;

    }

    public static G1Point HashToG1_1(BigInteger num) throws Exception {

        // 将 BigInteger 转换成字节数组
        byte[] bytes = num.toByteArray();
        BigInteger modResult = new BigInteger("0");
        // 使用 SHA-256 对字节数组进行哈希
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(bytes);

            // 将哈希结果转换回 BigInteger
            BigInteger hashBigInt = new BigInteger(1, hashBytes);

            // 对结果进行模运算，使其落在大素数内
            modResult = hashBigInt.mod(q);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] resultData = AltBn128.HashToG1(modResult);
        G1Point result = Util.deserializeG1(resultData);
        return result;

    }

    public static G1Point HashToG1_2(String message) throws Exception {

        byte[] bytes = message.getBytes();
        BigInteger modResult = new BigInteger("0");
        // 使用 SHA-256 对字节数组进行哈希
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(bytes);

            // 将哈希结果转换回 BigInteger
            BigInteger hashBigInt = new BigInteger(1, hashBytes);

            // 对结果进行模运算，使其落在大素数内
            modResult = hashBigInt.mod(q);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] resultData = AltBn128.HashToG1(modResult);
        G1Point result = Util.deserializeG1(resultData);
        return result;

    }


}
