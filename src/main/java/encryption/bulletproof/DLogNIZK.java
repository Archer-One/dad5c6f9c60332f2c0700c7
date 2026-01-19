package encryption.bulletproof;

/**
 * 非交互式离散对数零知识证明（NIZK）：
 * 1) 单基点 Schnorr 证明
 * 2) 双基点 矩阵 Schnorr 证明
 *
 * 使用 Fiat–Shamir 变换，通过 Transcript 来派生挑战值。
 */
public final class DLogNIZK {

    /** ------------------- 单基点证明 ------------------- **/

    public static class SingleBaseProof {
        public final Point R;    // 承诺 R = r·G
        public final Scalar s;   // 响应 s = r + c·x

        public SingleBaseProof(Point R, Scalar s) {
            this.R = R;
            this.s = s;
        }
    }

    /**
     * Non-interactive Prove for single-base discrete log:
     *   Public: G ∈ G1, P = x·G
     *   Secret: x
     *   Returns proof = (R, s) with
     *     R = r·G,
     *     c = H(transcript || "P" || P || "R" || R),
     *     s = r + c·x mod n
     *
     * @param G  基点 G
     * @param x  秘密标量 x
     * @param ts Fiat–Shamir Transcript（初始化时可写 domain）
     * @return   SingleBaseProof
     */
    public static SingleBaseProof proveSingle(Point G, Scalar x, Transcript ts) {
        // 1. 计算公钥 P = x·G
        Point P = G.mul(x);

        // 2. 随机选 r
        Scalar r = Scalar.random();

        // 3. 计算承诺 R = r·G
        Point R = G.mul(r);

        // 4. 写入 transcript: "P" || P || "R" || R
        ts.appendPoint("P", P.toBytes());
        ts.appendPoint("R", R.toBytes());

        // 5. 派生挑战 c = H(...)
        Scalar c = ts.challengeScalar("c");

        // 6. 计算响应 s = r + c·x
        Scalar s = r.add( c.mul(x) );

        return new SingleBaseProof(R, s);
    }

    /**
     * Verify single-base discrete log NIZK:
     *   Check s·G == R + c·P
     *
     * @param G     基点 G
     * @param P     公钥 P = x·G
     * @param proof SingleBaseProof 包含 R, s
     * @param ts    与 Prove 时同样初始化过的 Transcript
     * @return      验证是否通过
     */
    public static boolean verifySingle(Point G, Point P,
                                       SingleBaseProof proof,
                                       Transcript ts) {
        // 1. 将公钥 P、承诺 R 写入 transcript，挑战应与 Prove 时一致
        ts.appendPoint("P", P.toBytes());
        ts.appendPoint("R", proof.R.toBytes());

        // 2. 重放挑战 c
        Scalar c = ts.challengeScalar("c");

        // 3. 计算左侧 s·G
        Point sG = G.mul(proof.s);

        // 4. 计算右侧 R + c·P
        Point cP = P.mul(c);
        Point rhs = proof.R.add(cP);

        // 5. 比较是否相等
        return sG.equals(rhs);
    }


    /** ------------------- 双基点证明 ------------------- **/

    public static class TwoBaseProof {
        public final Point R;     // 承诺 R = r1·G + r2·H
        public final Scalar s1;   // 响应 s1 = r1 + c·a
        public final Scalar s2;   // 响应 s2 = r2 + c·b

        public TwoBaseProof(Point R, Scalar s1, Scalar s2) {
            this.R  = R;
            this.s1 = s1;
            this.s2 = s2;
        }
    }

    /**
     * Non-interactive Prove for two-base discrete log:
     *   Public: G, H ∈ G1, P = a·G + b·H
     *   Secret: (a, b)
     *   Returns proof = (R, s1, s2) with
     *     R  = r1·G + r2·H,
     *     c  = H(transcript || "G" || G || "H" || H || "P" || P || "R" || R),
     *     s1 = r1 + c·a mod n,  s2 = r2 + c·b mod n
     *
     * @param G  基点 G
     * @param H  基点 H
     * @param a  秘密标量 a
     * @param b  秘密标量 b
     * @param ts Fiat–Shamir Transcript（初始化时可写 domain）
     * @return   TwoBaseProof
     */
    public static TwoBaseProof proveTwoBase(Point G, Point H,
                                            Scalar a, Scalar b,
                                            Transcript ts) {
        // 1. 计算公钥 P = a·G + b·H
        Point aG = G.mul(a);
        Point bH = H.mul(b);
        Point P  = aG.add(bH);

        // 2. 随机选 r1, r2
        Scalar r1 = Scalar.random();
        Scalar r2 = Scalar.random();

        // 3. 计算承诺 R = r1·G + r2·H
        Point r1G = G.mul(r1);
        Point r2H = H.mul(r2);
        Point R   = r1G.add(r2H);

        // 4. 写入 transcript: "G"||G, "H"||H, "P"||P, "R"||R
        ts.appendPoint("G", G.toBytes());
        ts.appendPoint("H", H.toBytes());
        ts.appendPoint("P", P.toBytes());
        ts.appendPoint("R", R.toBytes());

        // 5. 派生挑战 c
        Scalar c = ts.challengeScalar("c");

        // 6. 计算响应 s1 = r1 + c·a,   s2 = r2 + c·b
        Scalar s1 = r1.add( c.mul(a) );
        Scalar s2 = r2.add( c.mul(b) );

        return new TwoBaseProof(R, s1, s2);
    }

    /**
     * Verify two-base discrete log NIZK:
     *   Check s1·G + s2·H == R + c·P
     *
     * @param G     基点 G
     * @param H     基点 H
     * @param P     公钥 P = a·G + b·H
     * @param proof TwoBaseProof 包含 R, s1, s2
     * @param ts    与 Prove 时同样初始化过的 Transcript
     * @return      验证是否通过
     */
    public static boolean verifyTwoBase(Point G, Point H, Point P,
                                        TwoBaseProof proof,
                                        Transcript ts) {
        // 1. 写入 transcript：G, H, P, R
        ts.appendPoint("G", G.toBytes());
        ts.appendPoint("H", H.toBytes());
        ts.appendPoint("P", P.toBytes());
        ts.appendPoint("R", proof.R.toBytes());

        // 2. 重放挑战 c
        Scalar c = ts.challengeScalar("c");

        // 3. 计算左侧 s1·G + s2·H
        Point s1G = G.mul(proof.s1);
        Point s2H = H.mul(proof.s2);
        Point lhs = s1G.add(s2H);

        // 4. 计算右侧 R + c·P
        Point cP  = P.mul(c);
        Point rhs = proof.R.add(cP);

        // 5. 比较
        return lhs.equals(rhs);
    }
}
