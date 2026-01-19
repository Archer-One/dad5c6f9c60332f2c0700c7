package encryption.bulletproof;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * BN128 子群阶 r 的标量封装 + 向量工具。
 */
public final class Scalar {

    /* -------- 曲线阶 r (与 alt-bn128 G1/G2 子群同) -------- */
    private static final BigInteger R = new BigInteger(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617");
    private static final SecureRandom RNG = new SecureRandom();

    private final BigInteger v;                     // 0 ≤ v < r

    /* ---- 构造器 ---- */
    public Scalar(BigInteger bi) { v = bi.mod(R); }
    public static Scalar fromBig(BigInteger bi){ return new Scalar(bi); }
    public static Scalar fromLong(long x){ return new Scalar(BigInteger.valueOf(x)); }

    /* ---- 常用静态 ---- */
    public static Scalar zero(){ return new Scalar(BigInteger.ZERO); }
    public static Scalar one (){ return new Scalar(BigInteger.ONE ); }
    public static Scalar random(){ return new Scalar(new BigInteger(254, RNG)); }

    /* ---- 基本运算 ---- */
    public Scalar add(Scalar o){ return new Scalar(v.add(o.v)); }
    public Scalar sub(Scalar o){ return new Scalar(v.subtract(o.v)); }
    public Scalar mul(Scalar o){ return new Scalar(v.multiply(o.v)); }
    public Scalar neg()        { return new Scalar(R.subtract(v)); }
    public Scalar square()     { return this.mul(this); }
    public Scalar inv()        { return new Scalar(v.modInverse(R)); }
    public Scalar pow(int e){ Scalar res = one(); for(int i=0;i<e;i++) res = res.mul(this); return res; }

    /* ---- 转换 ---- */
    public BigInteger toBigInt() { return v; }
    public long toLong() { return v.longValue(); }
    public byte[] toBytes() {
        byte[] tmp = v.toByteArray();
        byte[] out = new byte[32];
        int off = 32 - tmp.length;
        System.arraycopy(tmp,0,out,off,tmp.length);
        return out;
    }

    /* ---- 向量工具 (供 Bulletproofs 使用) ---- */
    public static List<Scalar> fill(int n, Scalar c){
        return new ArrayList<>(Collections.nCopies(n, c));
    }
    public static List<Integer> toBits(long val,int n){
        List<Integer> bits=new ArrayList<>(n);
        for(int i=0;i<n;i++) bits.add(((val>>i)&1L)==1?1:0);
        return bits;
    }
    public static List<Scalar> fromBits(List<Integer> bits){
        List<Scalar> out=new ArrayList<>(bits.size());
        for(int b:bits) out.add(b==0?zero():one());
        return out;
    }
    public static List<Scalar> randomVector(int n){
        List<Scalar> v=new ArrayList<>(n);
        for(int i=0;i<n;i++) v.add(random());
        return v;
    }
    private static void chk(List<?> a,List<?> b){
        if(a.size()!=b.size()) throw new IllegalArgumentException("length mismatch");
    }
    public static List<Scalar> vectorAdd(List<Scalar>a,List<Scalar>b){
        chk(a,b); List<Scalar> r=new ArrayList<>(a.size());
        for(int i=0;i<a.size();i++) r.add(a.get(i).add(b.get(i))); return r;
    }
    public static List<Scalar> vectorSub(List<Scalar>a,List<Scalar>b){
        chk(a,b); List<Scalar> r=new ArrayList<>(a.size());
        for(int i=0;i<a.size();i++) r.add(a.get(i).sub(b.get(i))); return r;
    }
    public static List<Scalar> scalarMul(List<Scalar>v,Scalar k){
        List<Scalar> r=new ArrayList<>(v.size());
        for(Scalar s:v) r.add(s.mul(k)); return r;
    }
    public static Scalar innerProduct(List<Scalar>a,List<Scalar>b){
        chk(a,b); Scalar acc=zero();
        for(int i=0;i<a.size();i++) acc=acc.add(a.get(i).mul(b.get(i)));
        return acc;
    }
    public static List<Scalar> hadamard(List<Scalar>a,List<Scalar>b){
        chk(a,b); List<Scalar> r=new ArrayList<>(a.size());
        for(int i=0;i<a.size();i++) r.add(a.get(i).mul(b.get(i))); return r;
    }
    public static List<Scalar> powersOf(Scalar base,int n){
        List<Scalar> out=new ArrayList<>(n); Scalar cur=one();
        for(int i=0;i<n;i++){ out.add(cur); cur=cur.mul(base); } return out;
    }
    public static List<Scalar> inverseVector(List<Scalar>v){
        List<Scalar> out=new ArrayList<>(v.size());
        for(Scalar s:v) out.add(s.inv()); return out;
    }
    public static List<Scalar> vectorOfOnes(int n){ return fill(n,one()); }
    public static List<Scalar> expandAndMerge(List<Scalar>s,Scalar l,Scalar r){
        int n=s.size(); List<Scalar> out=new ArrayList<>(n*2);
        for(Scalar si:s) out.add(si.mul(l));
        for(Scalar si:s) out.add(si.mul(r));
        return out;
    }

    /* ---- equals / hash ---- */
    @Override public boolean equals(Object o){
        return o instanceof Scalar && v.equals(((Scalar)o).v);
    }
    @Override public int hashCode(){ return v.hashCode(); }
    @Override public String toString(){ return v.toString(); }
}
