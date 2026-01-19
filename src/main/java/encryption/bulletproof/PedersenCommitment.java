package encryption.bulletproof;

import org.aion.tetryon.Fp;
import org.aion.tetryon.G1Point;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Pedersen generators (g, h) + 单值与向量承诺；在原有代码上添加内置测试与简单基准。 */
public class PedersenCommitment {
    public final Point g;   // 基点 g
    public final Point h;   // 基点 h（与 g 离散对数未知）

    public PedersenCommitment() {
//        this.g = Point.hashToPoint("Pedersen.g".getBytes(StandardCharsets.UTF_8));
//        this.h = Point.hashToPoint("Pedersen.h".getBytes(StandardCharsets.UTF_8));

        Fp ax = new Fp(new BigInteger("222480c9f95409bfa4ac6ae890b9c150bc88542b87b352e92950c340458b0c09", 16));
        Fp ay = new Fp(new BigInteger("2976efd698cf23b414ea622b3f720dd9080d679042482ff3668cb2e32cad8ae2", 16));
        Fp bx = new Fp(new BigInteger("1bd20beca3d8d28e536d2b5bd3bf36d76af68af5e6c96ca6e5519ba9ff8f5332", 16));
        Fp by = new Fp(new BigInteger("2a53edf6b48bcf5cb1c0b4ad1d36dfce06a79dcd6526f1c386a14d8ce4649844", 16));


        G1Point g = new G1Point(ax, ay);
        G1Point h = new G1Point(bx, by);


        this.g = new Point(g);
        this.h = new Point(h);
    }

    public PedersenCommitment(Point g, Point h) {
        this.g = g;
        this.h = h;
    }

    /** C = g^v · h^r */
    public Point commit(Scalar v, Scalar r) {
        return g.mul(v).add(h.mul(r));
    }

    /** C = Σ aᵢ·Gᵢ + Σ bᵢ·Hᵢ + r·h  */
    public Point commitVec(List<Point> G, List<Point> H,
                           List<Scalar> a, List<Scalar> b,
                           Scalar r) {
        return Point.msm(G, a)
                .add(Point.msm(H, b))
                .add(h.mul(r));
    }

    /* ======================= 内置测试 & 基准 ======================= */
    private static final int ITER = 50;      // 单值承诺与同态性测试迭代
    private static final int VEC_N = 32;     // 向量承诺维度
    private static final int VEC_ITER = 20;  // 向量承诺测试迭代

    /** 运行全部自测 */
    public static void selfTest() {
        PedersenCommitment pc = new PedersenCommitment();
        testCommitCorrectness(pc);
        testCommitHomomorphism(pc);
        testCommitVecCorrectness(pc);
        testCommitVecLengthMismatch(pc);
        bench(pc);
        System.out.println("全部 PedersenCommitment 自测完成 ✅");
    }

    /** 单值 commit 正确性与序列化一致性 */
    private static void testCommitCorrectness(PedersenCommitment pc) {
        for (int i = 0; i < ITER; i++) {
            Scalar v = Scalar.random();
            Scalar r = Scalar.random();

            Point C = pc.commit(v, r);
            Point expected = pc.g.mul(v).add(pc.h.mul(r));
            assertEq("commit correctness", expected, C);

            // 序列化/反序列化一致性
            Point restored = Point.fromBytes(C.toBytes());
            assertEq("commit (serialize/deserialize)", C, restored);
        }
        System.out.println("[OK] 单值 commit 正确性/序列化测试通过 (" + ITER + " 次)");
    }

    /** 同态性：C(v1,r1)+C(v2,r2) == g^{v1}+g^{v2}+h^{r1}+h^{r2} */
    private static void testCommitHomomorphism(PedersenCommitment pc) {
        for (int i = 0; i < ITER; i++) {
            Scalar v1 = Scalar.random();
            Scalar r1 = Scalar.random();
            Scalar v2 = Scalar.random();
            Scalar r2 = Scalar.random();

            Point C1 = pc.commit(v1, r1);
            Point C2 = pc.commit(v2, r2);
            Point sum = C1.add(C2);

            Point expected = Point.msm(
                    Arrays.asList(pc.g, pc.g, pc.h, pc.h),
                    Arrays.asList(v1,   v2,   r1,   r2)
            );
            assertEq("commit homomorphism", expected, sum);
        }
        System.out.println("[OK] 单值 commit 同态性测试通过 (" + ITER + " 次)");
    }

    /** 向量 commitVec 正确性 */
    private static void testCommitVecCorrectness(PedersenCommitment pc) {
        List<Point> G = new ArrayList<>(VEC_N);
        List<Point> H = new ArrayList<>(VEC_N);
        for (int i = 0; i < VEC_N; i++) {
            G.add(Point.hashToPoint(("PC.G." + i).getBytes(StandardCharsets.UTF_8)));
            H.add(Point.hashToPoint(("PC.H." + i).getBytes(StandardCharsets.UTF_8)));
        }
        for (int t = 0; t < VEC_ITER; t++) {
            List<Scalar> a = randScalars(VEC_N);
            List<Scalar> b = randScalars(VEC_N);
            Scalar r = Scalar.random();
            Point Cvec = pc.commitVec(G, H, a, b, r);
            Point manual = Point.msm(G, a).add(Point.msm(H, b)).add(pc.h.mul(r));
            assertEq("commitVec correctness", manual, Cvec);
        }
        System.out.println("[OK] 向量 commitVec 正确性测试通过 (" + VEC_ITER + " 次, 维度=" + VEC_N + ")");
    }

    /** commitVec 维度不一致异常 */
    private static void testCommitVecLengthMismatch(PedersenCommitment pc) {
        List<Point> G = new ArrayList<>(VEC_N);
        List<Point> H = new ArrayList<>(VEC_N);
        for (int i = 0; i < VEC_N; i++) {
            G.add(Point.hashToPoint(("PC.G." + i).getBytes(StandardCharsets.UTF_8)));
            H.add(Point.hashToPoint(("PC.H." + i).getBytes(StandardCharsets.UTF_8)));
        }
        try {
            List<Scalar> aBad = randScalars(VEC_N + 1);
            List<Scalar> b = randScalars(VEC_N);
            pc.commitVec(G, H, aBad, b, Scalar.random());
            throw new AssertionError("commitVec 未抛出长度不匹配异常");
        } catch (IllegalArgumentException ok) {
            System.out.println("[OK] commitVec 长度不一致时正确抛出 IllegalArgumentException");
        }
    }

    /** 简单基准：commit 与 commitVec 平均耗时 */
    private static void bench(PedersenCommitment pc) {
        long totalCommit = 0L;
        for (int i = 0; i < ITER; i++) {
            Scalar v = Scalar.random();
            Scalar r = Scalar.random();
            long t0 = System.nanoTime();
            Point C = pc.commit(v, r);
            long t1 = System.nanoTime();
            totalCommit += (t1 - t0);
        }
        double avgCommitMs = totalCommit / (double) ITER / 1_000_000.0;
        System.out.printf("commit 平均耗时（%d 次）: %.6f ms\n", ITER, avgCommitMs);

        List<Point> G = new ArrayList<>(VEC_N);
        List<Point> H = new ArrayList<>(VEC_N);
        for (int i = 0; i < VEC_N; i++) {
            G.add(Point.hashToPoint(("PC.G." + i).getBytes(StandardCharsets.UTF_8)));
            H.add(Point.hashToPoint(("PC.H." + i).getBytes(StandardCharsets.UTF_8)));
        }
        long totalCommitVec = 0L;
        for (int t = 0; t < VEC_ITER; t++) {
            List<Scalar> a = randScalars(VEC_N);
            List<Scalar> b = randScalars(VEC_N);
            Scalar r = Scalar.random();
            long t0 = System.nanoTime();
            Point Cvec = pc.commitVec(G, H, a, b, r);
            long t1 = System.nanoTime();
            totalCommitVec += (t1 - t0);
        }
        double avgCommitVecMs = totalCommitVec / (double) VEC_ITER / 1_000_000.0;
        System.out.printf("commitVec 平均耗时（%d 次, 维度=%d）: %.6f ms\n", VEC_ITER, VEC_N, avgCommitVecMs);
    }

    /* ======================= 辅助函数 ======================= */
    private static List<Scalar> randScalars(int n) {
        List<Scalar> out = new ArrayList<>(n);
        for (int i = 0; i < n; i++) out.add(Scalar.random());
        return out;
    }

    private static void assertEq(String name, Point expected, Point actual) {
        if (!expected.equals(actual)) {
            throw new AssertionError(name + " failed: expected " + expected + ", actual " + actual);
        }
    }

    /** 直接运行本类即可触发自测 */
    public static void main(String[] args) {
        selfTest();
    }
}
