package encryption.bulletproof;

import java.util.ArrayList;
import java.util.List;

/**
 * Inner-Product Proof 〈l,r〉=t  —— 对应 Bulletproofs 论文 §4.2
 */
public final class InnerProductProof {

    /* 公开字段（序列化时需要） */
    public final List<Point> L;     // 每轮左承诺  Lᵢ
    public final List<Point> R;     // 每轮右承诺  Rᵢ
    public final Scalar a;          // 压缩后标量  a (= l₀)
    public final Scalar b;          // 压缩后标量  b (= r₀)
    public final Point g2;
    public final Point h2;

    public InnerProductProof(List<Point> L, List<Point> R, Scalar a, Scalar b, Point g2, Point h2) {
        this.L = L;  this.R = R;  this.a = a;  this.b = b; this.g2=g2; this.h2=h2;
    }

    /* ===================================================================
     *                            ——  Prover  ——
     * =================================================================== */
    public static InnerProductProof prove(List<Scalar> l,
                                          List<Scalar> r,
                                          BulletproofGens gens,
                                          Transcript ts) {

        /* ---------- 防御性拷贝，避免就地修改影响外部 ---------- */
        l = new ArrayList<>(l);
        r = new ArrayList<>(r);

        int n = l.size();
        if (Integer.bitCount(n) != 1)
            throw new IllegalArgumentException("length must be power-of-2");

        /* ---------- 复制生成器向量 ---------- */
        List<Point> G = new ArrayList<>(gens.G.subList(0, n));
        List<Point> H = new ArrayList<>(gens.H.subList(0, n));

        List<Point> Lvec = new ArrayList<>();
        List<Point> Rvec = new ArrayList<>();

        /* =========================================================
         *            递归压缩（共 log₂(n) 轮）
         * ========================================================= */
        while (n > 1) {
            int n2 = n >>> 1;                       // n / 2

            /* (1) 计算 c_L  和  c_R   —— 公式 (8) */
            Scalar cL = Scalar.innerProduct(l.subList(0, n2), r.subList(n2, n));
            Scalar cR = Scalar.innerProduct(l.subList(n2, n), r.subList(0, n2));

            /* (2) 生成承诺 Lᵢ , Rᵢ —— 公式 (7) */
            Point Li = Point.msm(G.subList(n2, n), l.subList(0, n2))
                    .add(Point.msm(H.subList(0, n2), r.subList(n2, n)))
                    .add(gens.u.mul(cL));

            Point Ri = Point.msm(G.subList(0, n2), l.subList(n2, n))
                    .add(Point.msm(H.subList(n2, n), r.subList(0, n2)))
                    .add(gens.u.mul(cR));

            Lvec.add(Li);
            Rvec.add(Ri);

            /* (3) 将 Lᵢ, Rᵢ 写入 transcript → 得到挑战 xᵢ */
            ts.appendPoint("L", Li.toBytes());
            ts.appendPoint("R", Ri.toBytes());
            Scalar x     = ts.challengeScalar("x");   // xᵢ
            Scalar xInv  = x.inv();                   // xᵢ⁻¹

            /* (4) 线性合并向量与生成器 —— 公式 (9)(10) */
            for (int i = 0; i < n2; i++) {
                l.set(i, l.get(i)      .mul(x)   .add(l.get(i + n2).mul(xInv)));
                r.set(i, r.get(i)      .mul(xInv).add(r.get(i + n2).mul(x)));
                G.set(i, G.get(i)      .mul(xInv).add(G.get(i + n2).mul(x)));
                H.set(i, H.get(i)      .mul(x)   .add(H.get(i + n2).mul(xInv)));
            }

            /* (5) 折半向量长度，进入下一轮 */
            l = l.subList(0, n2);
            r = r.subList(0, n2);
            G = G.subList(0, n2);
            H = H.subList(0, n2);
            n = n2;
        }

        /* ---------- 递归结束：l,r,G,H  均只剩 1 元素 ---------- */
        return new InnerProductProof(Lvec, Rvec, l.get(0), r.get(0),G.get(0),H.get(0));
    }

    /* ===================================================================
     *                            —— Verifier ——
     * =================================================================== */
    public boolean verify(Point P, BulletproofGens gens, Transcript ts) {

        int rounds = L.size();
        int n      = 1 << rounds;                         // 原向量长度

        /* (1) 重播挑战 xᵢ, xᵢ⁻¹ */
        Scalar[] x  = new Scalar[rounds];
        Scalar[] xInv = new Scalar[rounds];

        for (int i = 0; i < rounds; i++) {
            ts.appendPoint("L", L.get(i).toBytes());
            ts.appendPoint("R", R.get(i).toBytes());
            x[i] = ts.challengeScalar("x");
            xInv[i] = x[i].inv();
        }

        /* (2) 计算 Σ Lᵢ·xᵢ² + Σ Rᵢ·xᵢ⁻²  →  得到 P′ */
        Point Pprime = P;
        for (int i = 0; i < rounds; i++) {
            Pprime = Pprime.add( L.get(i).mul( x[i].square() ) )
                    .add( R.get(i).mul( xInv[i].square() ) );
        }

        /* (3) 生成组合权重 s_j  (公式 11) */
        List<Scalar> s = Scalar.vectorOfOnes(1);          // 长度 1
        for (int i = rounds - 1; i >= 0; i--)
            s = Scalar.expandAndMerge(s, xInv[i], x[i]);   // new: reverse order

        List<Scalar> sInv = Scalar.inverseVector(s);      // sⱼ⁻¹

        /* (4) 右侧值：
               R = Σ s_j · G_j + Σ s_j⁻¹ · H_j + u·a·b                */
        Point RHS = g2.mul(a)
                .add(h2.mul(b))
                .add(gens.u.mul(a.mul(b)));

        return RHS.equals(Pprime);
    }


    public static InnerProductProof prove_1(List<Scalar> l,
                                            List<Scalar> r,
                                            BulletproofGens gens,
                                            Scalar y,            // <— 新增
                                            Transcript ts) {

        l = new ArrayList<>(l);
        r = new ArrayList<>(r);

        int n = l.size();
        if (Integer.bitCount(n) != 1)
            throw new IllegalArgumentException("length must be power-of-2");

        /* ---------- 生成 h′ = h_i^{y^{-i}} ---------- */
        List<Point> Hprime = new ArrayList<>(n);
        List<Scalar> yInvPows = Scalar.inverseVector(Scalar.powersOf(y, n));
        for (int i = 0; i < n; i++)
            Hprime.add( gens.H.get(i).mul( yInvPows.get(i) ) );

        /* ---------- 拷贝生成器向量 ---------- */
        List<Point> G = new ArrayList<>(gens.G.subList(0, n));
        List<Point> H = new ArrayList<>(Hprime);          // ← 用 h′ 替换原 H

        List<Point> Lvec = new ArrayList<>();
        List<Point> Rvec = new ArrayList<>();

        while (n > 1) {
            int n2 = n >>> 1;

            Scalar cL = Scalar.innerProduct(l.subList(0, n2), r.subList(n2, n));
            Scalar cR = Scalar.innerProduct(l.subList(n2, n), r.subList(0, n2));

            Point Li = Point.msm(G.subList(n2, n), l.subList(0, n2))
                    .add(Point.msm(H.subList(0, n2), r.subList(n2, n)))
                    .add(gens.u.mul(cL));

            Point Ri = Point.msm(G.subList(0, n2), l.subList(n2, n))
                    .add(Point.msm(H.subList(n2, n), r.subList(0, n2)))
                    .add(gens.u.mul(cR));

            Lvec.add(Li);
            Rvec.add(Ri);

            ts.appendPoint("L", Li.toBytes());
            ts.appendPoint("R", Ri.toBytes());
            Scalar x = ts.challengeScalar("x");
            Scalar xInv = x.inv();

            for (int i = 0; i < n2; i++) {
                l.set(i, l.get(i).mul(x).add( l.get(i+n2).mul(xInv) ));
                r.set(i, r.get(i).mul(xInv).add( r.get(i+n2).mul(x) ));
                G.set(i, G.get(i).mul(xInv).add( G.get(i+n2).mul(x) ));
                H.set(i, H.get(i).mul(x).add( H.get(i+n2).mul(xInv) ));
            }
            l = l.subList(0, n2);   r = r.subList(0, n2);
            G = G.subList(0, n2);   H = H.subList(0, n2);
            n = n2;
        }
        /* 返回时 G/H 只剩 1 元素 —— 记为 g2, h2 */
        return new InnerProductProof(Lvec, Rvec, l.get(0), r.get(0),
                G.get(0), H.get(0));
    }

    /* ===================================================================
     * 新  Verifier：verify_1 —— 与 prove_1 对应，使用 h′
     * =================================================================== */
    public boolean verify_1(Point P,
                            BulletproofGens gens,
                            Scalar y,               // <— 新增
                            Transcript ts,
                            Point mu) {

        int rounds = L.size();
        int n      = 1 << rounds;

        /* ---------- 重放挑战序列 ---------- */
        Scalar[] x = new Scalar[rounds];
        Scalar[] xInv = new Scalar[rounds];
        for (int i = 0; i < rounds; i++) {
            ts.appendPoint("L", L.get(i).toBytes());
            ts.appendPoint("R", R.get(i).toBytes());
            x[i] = ts.challengeScalar("x");
            xInv[i] = x[i].inv();
        }

        /* ---------- 累加得到 P′ ---------- */
        Point Pprime = P;
        for (int i = 0; i < rounds; i++) {
            Pprime = Pprime.add( L.get(i).mul( x[i].square() ) )
                    .add( R.get(i).mul( xInv[i].square() ) );
        }

        /* ---------- 生成组合权重 s_j ---------- */
        List<Scalar> s = Scalar.vectorOfOnes(1);
        for (int i = rounds - 1; i >= 0; i--)
            s = Scalar.expandAndMerge(s, xInv[i], x[i]);    // reverse order

        /* ---------- 生成 h′ 与 RHS ---------- */
        List<Point> Hprime = new ArrayList<>(n);
        List<Scalar> yInvPows = Scalar.inverseVector(Scalar.powersOf(y, n));
        for (int i = 0; i < n; i++)
            Hprime.add( gens.H.get(i).mul( yInvPows.get(i) ) );

        Point RHS = g2.mul(a)
                .add(h2.mul(b))
                .add(gens.u.mul(a.mul(b)))
                .add(mu);           // u·a·b

        return RHS.equals(Pprime);
    }
}