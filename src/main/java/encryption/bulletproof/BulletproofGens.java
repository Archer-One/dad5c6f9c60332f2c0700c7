package encryption.bulletproof;

import java.util.ArrayList;
import java.util.List;

/**
 * Bulletproofs 向量生成器：Gᵢ、Hᵢ、u
 */
public final class BulletproofGens {

    public final List<Point> G;
    public final List<Point> H;
    public final Point u;

    /**
     * @param bits    单值位宽 (8 / 16 / 32 / 64 / …), 必须是 2 的幂
     * @param parties 可并行证明数量 (聚合证明时用)，单值填 1
     */
    public BulletproofGens(int bits, int parties) {
        int n = bits * parties;
        G = new ArrayList<>(n);
        H = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            G.add(Point.hashToPoint(("BP.G" + i).getBytes()));
            H.add(Point.hashToPoint(("BP.H" + i).getBytes()));
        }
        u = Point.hashToPoint("BP.u".getBytes());
    }
}