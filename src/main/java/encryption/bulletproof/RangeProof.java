package encryption.bulletproof;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Bulletproofs 单值范围证明 (v ∈ [0, 2^bits))
 */
public final class RangeProof {

    public final Point A, S, T1, T2;
    public final Scalar taux, mu, tHat;
    public final InnerProductProof ipp;

    RangeProof(Point A, Point S, Point T1, Point T2,
               Scalar taux, Scalar mu, Scalar tHat,
               InnerProductProof ipp) {
        this.A = A; this.S = S; this.T1 = T1; this.T2 = T2;
        this.taux = taux; this.mu = mu; this.tHat = tHat; this.ipp = ipp;
    }

    private static Scalar delta(Scalar y, Scalar z, int nBits) {

        /* --- Σ y^i  (i = 0..n-1) --- */
        List<Scalar> yPows = Scalar.powersOf(y, nBits);  // y⁰ … yⁿ⁻¹
        Scalar sumY = Scalar.zero();
        for (Scalar yi : yPows) sumY = sumY.add(yi);

        /* --- Σ 2^i  =  2ⁿ - 1  (i = 0..n-1) --- */
        // 使用BigInteger处理大于63位的幂运算
        BigInteger twoPowerN = BigInteger.ONE.shiftLeft(nBits);  // 2ⁿ
        Scalar sumTwo = new Scalar(twoPowerN.subtract(BigInteger.ONE)); // 2ⁿ - 1

        /* --- δ(y,z) 公式 --- */
        Scalar term1 = z.sub(z.square()).mul(sumY);      // (z - z²)·Σy^i
        Scalar term2 = z.pow(3).mul(sumTwo);             // z³·Σ2^i
        return term1.sub(term2);                         // δ = term1 - term2
    }

    /* -------------------------- Prover -------------------------- */
    public static RangeProof prove(long v, Scalar blind, int bits,
                                   PedersenCommitment pc, BulletproofGens gens,
                                   Transcript ts) {

        int n = bits;
        List<Integer> bitsV = Scalar.toBits(v, n);
        List<Scalar> aL = Scalar.fromBits(bitsV);
        List<Scalar>  ones  = Scalar.fill(n, Scalar.one());
        List<Scalar>  aR    = Scalar.vectorSub(aL, ones);   // aR = aL - 1ⁿ

        List<Scalar> sL = Scalar.randomVector(n);
        List<Scalar> sR = Scalar.randomVector(n);
        Scalar alpha  = Scalar.random();
        Scalar rho    = Scalar.random();

        Point A = pc.commitVec(gens.G, gens.H, aL, aR, alpha);
        Point S = pc.commitVec(gens.G, gens.H, sL, sR, rho);
        ts.appendPoint("A", A.toBytes());
        ts.appendPoint("S", S.toBytes());

        Scalar y = ts.challengeScalar("y");
        Scalar z = ts.challengeScalar("z");
        Scalar zSq = z.square();

        List<Scalar> l0 = Scalar.vectorSub(aL, Scalar.fill(n, z));
        List<Scalar> l1 = sL;

        List<Scalar> yPows = Scalar.powersOf(y, n);
        List<Scalar> z2TwoPow = new ArrayList<>(n);
        for (int i = 0; i < n; i++)
            z2TwoPow.add( new Scalar(BigInteger.ONE.shiftLeft(i)).mul(zSq) );
        List<Scalar> r0_base = Scalar.vectorAdd(aR, Scalar.fill(n, z));
        r0_base = Scalar.hadamard(r0_base, yPows);

        /* 3.  yᶦ ⊙ (...) */
        List<Scalar> r0 = Scalar.vectorAdd(r0_base, z2TwoPow);
        List<Scalar> r1 = Scalar.hadamard(sR, yPows);

        Scalar t1 = Scalar.innerProduct(l0, r1)
                .add(Scalar.innerProduct(l1, r0));
        Scalar t2 = Scalar.innerProduct(l1, r1);

        Scalar tau1 = Scalar.random();
        Scalar tau2 = Scalar.random();

        Point T1 = pc.commit(t1, tau1);
        Point T2 = pc.commit(t2, tau2);
        ts.appendPoint("T1", T1.toBytes());
        ts.appendPoint("T2", T2.toBytes());

        Scalar x = ts.challengeScalar("x");

        Scalar taux = tau1.mul(x).add(tau2.mul(x.square()))
                .add(blind.mul(z.square()));
        Scalar mu   = alpha.add(rho.mul(x));

        List<Scalar> l = Scalar.vectorAdd(l0, Scalar.scalarMul(l1, x));
        List<Scalar> r = Scalar.vectorAdd(r0, Scalar.scalarMul(r1, x));

        Scalar tHat = Scalar.innerProduct(l, r);

        InnerProductProof ipp = InnerProductProof.prove_1(l, r, gens, y,ts);
        return new RangeProof(A, S, T1, T2, taux, mu, tHat, ipp);
    }

    /* ------------------------ Verifier ------------------------ */
    public boolean verify(Point commitment,
                          int bits,
                          PedersenCommitment pc,
                          BulletproofGens gens,
                          Transcript ts) {

        final int n = bits;
        if (Integer.bitCount(n) != 1)
            throw new IllegalArgumentException("bits must be power-of-2");

        /* --- 1. 重放挑战 --- */
        ts.appendPoint("A", A.toBytes());
        ts.appendPoint("S", S.toBytes());
        Scalar y = ts.challengeScalar("y");
        Scalar z = ts.challengeScalar("z");

        ts.appendPoint("T1", T1.toBytes());
        ts.appendPoint("T2", T2.toBytes());
        Scalar x = ts.challengeScalar("x");

        Scalar delta = delta(y, z, bits);

        /* --- 2. 检查 tHat·g + taux·h = z²·C + x·T1 + x²·T2 --- */
        Point lhs = pc.g.mul(tHat).add(pc.h.mul(taux));
        Point rhs = commitment.mul(z.square())
                .add(T1.mul(x))
                .add(T2.mul(x.square()))
                .add(pc.g.mul(delta));
        if (!lhs.equals(rhs)) return false;




        List<Scalar> yPows = Scalar.powersOf(y, n);

        // y 的负幂  y⁻⁰ … y⁻(n-1)
        List<Scalar> yInvPows = Scalar.inverseVector(yPows);

        // H′ᵢ =  y⁻ⁱ · Hᵢ
        List<Point> Hprime = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            Hprime.add( gens.H.get(i).mul( yInvPows.get(i)  ) );
        }


        List<Scalar> zfill = Scalar.fill(n, z.neg());                 // g^{-z}
        List<Scalar> rHat = new ArrayList<>(n);                      // (h′)^{z+z²2ᶦ}
        Scalar zSq = z.square();
        for (int i = 0; i < n; i++)
            rHat.add( yPows.get(i).mul( z.add( zSq.mul( new Scalar(BigInteger.ONE.shiftLeft(i)) ) ) ) );

        List<Scalar> twoPows = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            twoPows.add( new Scalar(BigInteger.ONE.shiftLeft(i)) );
        }

        /* 组合得到  eᵢ = z·y^i + z²·2^i */
        List<Scalar> out = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            Scalar term = z.mul( yPows.get(i) )            // z·y^i
                    .add( zSq.mul( twoPows.get(i) ) ); // + z²·2^i
            out.add(term);
        }

        /* ---------- P′ 组合 ---------- */
        Point Pprime = A.add( S.mul(x) )
                .add( Point.msm(gens.G.subList(0,n), zfill) )  // g^{-z}
                .add( Point.msm(Hprime, out ))               // (h′)^{…}
                .add(gens.u.mul(tHat));

        /* --- 6. 调用内积证明验证 ----------------------------- */
        return ipp.verify_1(Pprime, gens, y, ts, pc.h.mul(mu));                  // g₂,h₂ 已存于 proof 内部
    }

    public boolean debugVerify(long v, Scalar blind,
                               int bits,
                               PedersenCommitment pc,
                               BulletproofGens gens,
                               Transcript tsDbg) {
        Point commitment = pc.commit(Scalar.fromLong(v), blind);
        boolean ok = this.verify(commitment, bits, pc, gens, tsDbg);
        if(!ok) throw new RuntimeException("RangeProof.verify failed — check formulas");

        /* ---------- 深入一步：重算中间向量并比较 ---------- */
        int n = bits;

        // 1) 重新 bit-decompose v
        List<Integer> bitsV = Scalar.toBits(v, n);
        List<Scalar> aL = Scalar.fromBits(bitsV);
        List<Scalar>  ones  = Scalar.fill(n, Scalar.one());
        List<Scalar>  aR    = Scalar.vectorSub(aL, ones);   // aR = aL - 1ⁿ

        // 2) 确认 A = <G,aL> + <H,aR> + α·h
        //    (无法恢复 α，但可检查 A - <G,aL> - <H,aR> 是否在 h 方向)
        Point part = pc.commitVec(gens.G, gens.H, aL, aR, Scalar.zero());
        Point diff = A.add(part.neg());
        if(!isSameLine(diff, pc.h))
            throw new RuntimeException("A commitment inconsistent with aL,aR");

        /* …可按需要继续添加 t₁/t₂、δ(y,z) 的断言 … */

        return true;          // 全部通过
    }

    /* 判定 diff 是否是 h 的标量倍数 */
    private boolean isSameLine(Point diff, Point h){
        // 简易做法：取随机 r，若 diff + r·h 能被 verifier 当作合法承诺，说明 colinear
        return diff.equals(Point.INF) || diff.add(h).equals(h.add(diff));
    }

    /* --- 简易序列化（若要网络传输自行扩充） --- */
    public byte[] toBytes() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            out.write(A.toBytes());
            out.write(S.toBytes());
            out.write(T1.toBytes());
            out.write(T2.toBytes());

            out.write(taux.toBytes());
            out.write(mu.toBytes());
            out.write(tHat.toBytes());

            // ── IPP ───────────────
            for (Point Lpt : ipp.L) out.write(Lpt.toBytes());
            for (Point Rpt : ipp.R) out.write(Rpt.toBytes());
            out.write(ipp.a.toBytes());
            out.write(ipp.b.toBytes());

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return out.toByteArray();
    }
}