package global;

import encryption.bulletproof.Point;
import org.aion.tetryon.Fp;
import org.aion.tetryon.Fp2;
import org.aion.tetryon.G1Point;
import org.aion.tetryon.G2Point;

import java.math.BigInteger;

public class Global {
    public static Fp ax = new Fp(new BigInteger("222480c9f95409bfa4ac6ae890b9c150bc88542b87b352e92950c340458b0c09", 16));
    public static Fp ay = new Fp(new BigInteger("2976efd698cf23b414ea622b3f720dd9080d679042482ff3668cb2e32cad8ae2", 16));
    public static Fp bx = new Fp(new BigInteger("1bd20beca3d8d28e536d2b5bd3bf36d76af68af5e6c96ca6e5519ba9ff8f5332", 16));
    public static Fp by = new Fp(new BigInteger("2a53edf6b48bcf5cb1c0b4ad1d36dfce06a79dcd6526f1c386a14d8ce4649844", 16));


    public static Point g = new Point(new G1Point(ax, ay)) ;
    public static Point h = new Point(new G1Point(bx, by));

    public static G2Point hatG = new G2Point(
            new Fp2(
                    new BigInteger("10857046999023057135944570762232829481370756359578518086990519993285655852781"),
                    new BigInteger("11559732032986387107991004021392285783925812861821192530917403151452391805634")
            ),
            new Fp2(
                    new BigInteger("8495653923123431417604973247489272438418190587263600148770280649306958101930"),
                    new BigInteger("4082367875863433681332203403145435568316851327593401208105741076214120093531")
            )
    );

    public static int IDBITS = 128;
    public static int STATEBITS = 32;
    public static int VALUEBITS = 64;
}
