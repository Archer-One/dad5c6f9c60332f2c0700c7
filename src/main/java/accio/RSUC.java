package accio;

import encryption.bulletproof.Point;
import encryption.bulletproof.Scalar;
import org.aion.tetryon.*;

import java.math.BigInteger;

import static org.aion.tetryon.Pairing.pairing;

public class RSUC {
    public final Point g;   // 基点 g
    public final Point h;   // 基点 h（与 g 离散对数未知）

    public final G2Point hatG;

    public static void main(String[] args) throws Exception {
        Fp ax = new Fp(new BigInteger("222480c9f95409bfa4ac6ae890b9c150bc88542b87b352e92950c340458b0c09", 16));
        Fp ay = new Fp(new BigInteger("2976efd698cf23b414ea622b3f720dd9080d679042482ff3668cb2e32cad8ae2", 16));
        Fp bx = new Fp(new BigInteger("1bd20beca3d8d28e536d2b5bd3bf36d76af68af5e6c96ca6e5519ba9ff8f5332", 16));
        Fp by = new Fp(new BigInteger("2a53edf6b48bcf5cb1c0b4ad1d36dfce06a79dcd6526f1c386a14d8ce4649844", 16));


        Point g = new Point(new G1Point(ax, ay)) ;
        Point h = new Point(new G1Point(bx, by));

        G2Point hatG = new G2Point(
                new Fp2(
                        new BigInteger("10857046999023057135944570762232829481370756359578518086990519993285655852781"),
                        new BigInteger("11559732032986387107991004021392285783925812861821192530917403151452391805634")
                ),
                new Fp2(
                        new BigInteger("8495653923123431417604973247489272438418190587263600148770280649306958101930"),
                        new BigInteger("4082367875863433681332203403145435568316851327593401208105741076214120093531")
                )
        );


        RSUC rsuc = new RSUC(g,h,hatG);

        Scalar v = new Scalar(new BigInteger("435432532523543534543"));
        Scalar r = Scalar.random();
        KeyPair keyPair = rsuc.keyGen();
        AuthInfo authInfo = rsuc.authCom(v, keyPair.x0, keyPair.x1, r);

        boolean cmCheck = rsuc.vfCom(authInfo.cm, v ,r);
        if (!cmCheck){
            System.out.println("Cm check error!");
        }else {
            System.out.println("Cm check success!");
        }

        boolean authCheck = rsuc.vfAuth(authInfo.cm, authInfo.sig, keyPair.X0, keyPair.X1);
        if (!authCheck){
            System.out.println("Auth check error!");
        }else {
            System.out.println("Auth check success!");
        }

        Scalar r_ = Scalar.random();
        AuthInfo authInfo_ = rsuc.rdmAC(authInfo.cm, authInfo.sig, r_);
        boolean authCheck_ = rsuc.vfAuth(authInfo.cm, authInfo.sig, keyPair.X0, keyPair.X1);
        if (!authCheck_){
            System.out.println("blinded Auth check error!");
        }else {
            System.out.println("blinded Auth check success!");
        }

        Scalar a = new Scalar(new BigInteger("24332434"));
        AuthInfo authInfo1 = rsuc.updAC(authInfo_.cm, a, keyPair.x0, keyPair.x1);
        boolean authInfo1Check_ = rsuc.vfUpd(authInfo_.cm, a, authInfo1.cm, authInfo1.sig, keyPair.X0, keyPair.X1);
        if (!authInfo1Check_){
            System.out.println("updated Auth check error!");
        }else {
            System.out.println("updated Auth check success!");
        }
    }



    public RSUC(Point g, Point h, G2Point hatG) {
        this.g = g;
        this.h = h;
        this.hatG = hatG;
    }

    public KeyPair keyGen(){
        Scalar x0 = Scalar.random();
        Scalar x1 = Scalar.random();

        G2Point X0 = G2.ECTwistMul(hatG, x0.toBigInt());
        G2Point X1 = G2.ECTwistMul(hatG, x1.toBigInt());
        return new KeyPair(x0, x1, X0, X1);
    }

    public AuthInfo authCom(Scalar v, Scalar x0, Scalar x1, Scalar r){
        Point C0 = this.g.mul(r);

        Point vG = this.g.mul(v);
        Point rH = this.h.mul(r);
        Point C1 = vG.add(rH);

        CM cm = new CM(C0, C1);

        Scalar s = Scalar.random();
        Scalar sInv = s.inv();

        Point x0C0 = C0.mul(x0);
        Point x1C1 = C1.mul(x1);
        Point Z = this.g.add(x0C0).add(x1C1).mul(sInv);

        Point S = this.g.mul(s);

        G2Point hatS = G2.ECTwistMul(this.hatG, s.toBigInt());

        Point x0G = this.g.mul(x0);
        Point x1H = this.h.mul(x1);
        Point T = x0G.add(x1H).mul(sInv);
        Sig sig = new Sig(Z, S, T, hatS);
        return new AuthInfo(cm, sig);
    }

    public boolean vfCom(CM cm, Scalar v, Scalar r){
        Point C0 = this.g.mul(r);

        if (!cm.C0.equals(C0)){
            return false;
        }

        Point vG = this.g.mul(v);
        Point rH = this.h.mul(r);
        Point C1 = vG.add(rH);

        if (!cm.C1.equals(C1)){
            return false;
        }

        return true;

    }

    public boolean vfAuth(CM cm, Sig sig, G2Point X0, G2Point X1) throws Exception {

        G1Point[] e_l = new G1Point[]{sig.Z.neg().p, this.g.p, cm.C0.p, cm.C1.p};
        G2Point[] e_r = new G2Point[]{sig.hatS, this.hatG, X0, X1};
        boolean result =  pairing(e_l, e_r);
        if (!result){
            return false;
        }

        e_l = new G1Point[]{this.g.p, sig.S.neg().p};
        e_r = new G2Point[]{sig.hatS, this.hatG};
        result =  pairing(e_l, e_r);
        if (!result){
            return false;
        }

        e_l = new G1Point[]{sig.T.neg().p, this.g.p, this.h.p};
        e_r = new G2Point[]{sig.hatS, X0, X1};
        result =  pairing(e_l, e_r);
        if (!result){
            return false;
        }
        return true;
    }

    public AuthInfo rdmAC(CM cm, Sig sig, Scalar r){
        Scalar s = Scalar.random();
        Scalar sInv = s.inv();

        Point C0_ = cm.C0.add(this.g.mul(r));
        Point C1_ = cm.C1.add(this.h.mul(r));
        CM cm_ = new CM(C0_, C1_);

        Point rT = sig.T.mul(r);
        Point Z = sig.Z.add(rT).mul(sInv);
        Point S = sig.S.mul(s);
        G2Point hatS = G2.ECTwistMul(sig.hatS, s.toBigInt());
        Point T = sig.T.mul(sInv);
        Sig sig_ = new Sig(Z, S, T, hatS);
        return new AuthInfo(cm_, sig_);
    }

    public AuthInfo updAC(CM cm, Scalar a, Scalar x0, Scalar x1){
        Point C0 = cm.C0;
        Point C1 = cm.C1.add(this.g.mul(a));
        CM cm_ = new CM(C0, C1);

        Scalar s = Scalar.random();
        Scalar sInv = s.inv();

        Point x0C0 = C0.mul(x0);
        Point aG = this.g.mul(a);
        Point x1aG = cm.C1.add(aG).mul(x1);

        Point Z = this.g.add(x0C0).add(x1aG).mul(sInv);

        Point S = this.g.mul(s);

        G2Point hatS = G2.ECTwistMul(this.hatG, s.toBigInt());

        Point x0G = this.g.mul(x0);
        Point x1H = this.h.mul(x1);
        Point T = x0G.add(x1H).mul(sInv);
        Sig sig = new Sig(Z, S, T, hatS);
        return  new AuthInfo(cm_, sig);
    }

    public boolean vfUpd(CM cm, Scalar a, CM cm_, Sig sig, G2Point X0, G2Point X1) throws Exception {
        if (!cm.C0.equals(cm_.C0)){
            return false;
        }

        Point C1_ = cm.C1.add(this.g.mul(a));

        if (!C1_.equals(cm_.C1)){
            return false;
        }

        if(vfAuth(cm_, sig, X0, X1)){
            return true;
        }else {
            return false;
        }
    }

    public static class AuthInfo{
        public CM cm;
        public Sig sig;

        public AuthInfo(CM cm, Sig sig) {
            this.cm = cm;
            this.sig = sig;
        }

        @Override
        public String toString(){
            return cm.C0.toString()
                    + cm.C1.toBytes()
                    + sig.Z.toString()
                    + sig.S.toString()
                    + sig.T.toString()
                    + sig.hatS.toString();
        }
    }

    public static class KeyPair{
        public Scalar x0;
        public Scalar x1;
        public G2Point X0;
        public G2Point X1;

        public KeyPair(Scalar x0, Scalar x1, G2Point x01, G2Point x11) {
            this.x0 = x0;
            this.x1 = x1;
            X0 = x01;
            X1 = x11;
        }
    }

    public static class CM{
        public Point C0;
        public Point C1;

        public CM(Point c0, Point c1) {
            C0 = c0;
            C1 = c1;
        }
    }

    public static class Sig{
        public Point Z;
        public Point S;
        public Point T;
        public G2Point hatS;

        public Sig(Point z, Point s, Point t, G2Point hatS) {
            Z = z;
            S = s;
            T = t;
            this.hatS = hatS;
        }
    }
}

