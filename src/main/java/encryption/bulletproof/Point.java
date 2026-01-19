package encryption.bulletproof;

import org.aion.tetryon.G1;
import org.aion.tetryon.G1Point;
import org.aion.tetryon.Util;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.List;

/**
 * 适配 org.aion.tetryon.G1Point 的轻量包装，提供 Bulletproofs 需要的
 * add / mul / msm / hashToPoint / 序列化。
 */
public final class Point {

    public final G1Point p;
    public static final Point INF = new Point(G1Point.INF);

    public Point(G1Point p){ this.p = p; }

    /* -------- 基本运算 -------- */
    public Point add(Point q){
        // 如果有一方是无穷点，直接返回另一方
        if (this.equals(INF)) return q;
        if (q.equals(INF))    return this;
        try {
            return new Point(G1.add(p, q.p));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Point mul(Scalar k) {
        if (k.toBigInt().equals(BigInteger.ZERO)) return INF;  // 0·P = INF
        try {
            return new Point(G1.mul(p, k.toBigInt()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    public Point neg(){
        return new Point(G1.negate(p));
    }

    /* -------- 多标量乘：朴素累加 -------- */
    public static Point msm(List<Point> P, List<Scalar> k){
        if(P.size()!=k.size()) throw new IllegalArgumentException("len mismatch");
        Point acc = INF;
        for(int i=0;i<P.size();i++){
            if(!k.get(i).toBigInt().equals(BigInteger.ZERO))
                acc = acc.add( P.get(i).mul(k.get(i)) );
        }
        return acc;
    }

    /* -------- Hash-to-curve（借用 G1.HashToG1） -------- */
    public static Point hashToPoint(byte[] msg){
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(msg);
            BigInteger bi = new BigInteger(1, digest);
            return new Point(G1.HashToG1_1(bi));
        } catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    /* -------- 序列化 -------- */
    public byte[] toBytes(){
        return Util.serializeG1(p);
    }
    public static Point fromBytes(byte[] data){
        return new Point(Util.deserializeG1(data));
    }

    /* -------- equals / hash / toString -------- */
    @Override public boolean equals(Object o){
        return o instanceof Point && p.equals(((Point)o).p);
    }
    @Override public int hashCode(){ return p.hashCode(); }
    @Override public String toString(){ return p.toString(); }
}