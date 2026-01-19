package encryption.bulletproof;

import java.security.SecureRandom;

/**
 * 测试单基点和双基点非交互式离散对数零知识证明，
 * 测量 prove 和 verify 的耗时，取 50 次运行后的平均值。
 */
public class DLogNIZKTest {

    private static final SecureRandom RNG = new SecureRandom();
    private static final int ITERATIONS = 50;

    public static void main(String[] args) throws Exception {
        // 用 hashToPoint 得到两个不同的固定基点 G 和 H
        Point G = Point.hashToPoint("Demo.G".getBytes());
        Point H = Point.hashToPoint("Demo.H".getBytes());

        // 单基点测试
        System.out.println("=== Single-Base NIZK Proof Timing Test ===");
        long totalProveTimeSingle = 0;
        long totalVerifyTimeSingle = 0;
        for (int i = 0; i < ITERATIONS; i++) {
            // 生成秘密 x ∈ ℤₙ
            Scalar x = Scalar.random();
            // 计算公钥 P = x·G
            Point P = G.mul(x);
            // 生成证明并计时
            Transcript tsProve = new Transcript("SingleBaseDomain".getBytes());
            long startProve = System.nanoTime();
            DLogNIZK.SingleBaseProof proof = DLogNIZK.proveSingle(G, x, tsProve);
            long endProve = System.nanoTime();
            totalProveTimeSingle += (endProve - startProve);

            // 验证证明并计时
            Transcript tsVerify = new Transcript("SingleBaseDomain".getBytes());
            long startVerify = System.nanoTime();
            boolean ok = DLogNIZK.verifySingle(G, P, proof, tsVerify);
            long endVerify = System.nanoTime();
            totalVerifyTimeSingle += (endVerify - startVerify);

            if (!ok) {
                System.out.println("Single-base proof verification failed at iteration " + i);
            }
        }
        double avgProveSingle = totalProveTimeSingle / (double) ITERATIONS / 1_000_000.0;
        double avgVerifySingle = totalVerifyTimeSingle / (double) ITERATIONS / 1_000_000.0;
        System.out.printf("Average Single-base Prove Time: %.3f ms%n", avgProveSingle);
        System.out.printf("Average Single-base Verify Time: %.3f ms%n", avgVerifySingle);
        System.out.println();

        // 双基点测试
        System.out.println("=== Two-Base NIZK Proof Timing Test ===");
        long totalProveTimeTwo = 0;
        long totalVerifyTimeTwo = 0;
        for (int i = 0; i < ITERATIONS; i++) {
            // 生成秘密 (a, b) ∈ ℤₙ²
            Scalar a = Scalar.random();
            Scalar b = Scalar.random();
            // 计算公钥 P2 = a·G + b·H
            Point aG = G.mul(a);
            Point bH = H.mul(b);
            Point P2 = aG.add(bH);

            // 生成证明并计时
            Transcript tsProve2 = new Transcript("TwoBaseDomain".getBytes());
            long startProve2 = System.nanoTime();
            DLogNIZK.TwoBaseProof proof2 = DLogNIZK.proveTwoBase(G, H, a, b, tsProve2);
            long endProve2 = System.nanoTime();
            totalProveTimeTwo += (endProve2 - startProve2);

            // 验证证明并计时
            Transcript tsVerify2 = new Transcript("TwoBaseDomain".getBytes());
            long startVerify2 = System.nanoTime();
            boolean ok2 = DLogNIZK.verifyTwoBase(G, H, P2, proof2, tsVerify2);
            long endVerify2 = System.nanoTime();
            totalVerifyTimeTwo += (endVerify2 - startVerify2);

            if (!ok2) {
                System.out.println("Two-base proof verification failed at iteration " + i);
            }
        }
        double avgProveTwo = totalProveTimeTwo / (double) ITERATIONS / 1_000_000.0;
        double avgVerifyTwo = totalVerifyTimeTwo / (double) ITERATIONS / 1_000_000.0;
        System.out.printf("Average Two-base Prove Time: %.3f ms%n", avgProveTwo);
        System.out.printf("Average Two-base Verify Time: %.3f ms%n", avgVerifyTwo);
    }
}
