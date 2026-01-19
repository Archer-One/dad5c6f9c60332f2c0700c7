package lighthub;

import encryption.bulletproof.Point;
import encryption.bulletproof.Scalar;
import org.aion.tetryon.*;

import java.math.BigInteger;

import static org.aion.tetryon.Pairing.pairing;

public class RDBS {
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


        RDBS rdbs = new RDBS(g,h,hatG);

        Scalar v = new Scalar(new BigInteger("435432532523543534543"));
        Scalar r = Scalar.random();
        KeyPair keyPair = rdbs.keyGen();
        AuthInfo authInfo = rdbs.authCom(v, keyPair.x, r);

        boolean cmCheck = rdbs.vfCom(authInfo.cm, v ,r);
        if (!cmCheck){
            System.out.println("Cm check error!");
        }else {
            System.out.println("Cm check success!");
        }

        boolean authCheck = rdbs.vfAuth(authInfo.cm, authInfo.sig, keyPair.X);
        if (!authCheck){
            System.out.println("Auth check error!");
        }else {
            System.out.println("Auth check success!");
        }

        Scalar r_ = Scalar.random();
        AuthInfo authInfo_ = rdbs.rdmAC(authInfo.cm, authInfo.sig, r_);
        boolean authCheck_ = rdbs.vfAuth(authInfo.cm, authInfo.sig, keyPair.X);
        if (!authCheck_){
            System.out.println("blinded Auth check error!");
        }else {
            System.out.println("blinded Auth check success!");
        }

        Scalar value = new Scalar(new BigInteger("24332434"));
        Scalar blind_r = Scalar.random();
        Point amt = rdbs.genPedCom(value,blind_r);
        AuthInfo authInfo1 = rdbs.updAC(authInfo_.cm, keyPair.x);
        boolean authInfo1Check_ = rdbs.vfUpd(authInfo_.cm, amt, authInfo1.cm, authInfo1.sig, keyPair.X);
        if (!authInfo1Check_){
            System.out.println("updated Auth check error!");
        }else {
            System.out.println("updated Auth check success!");
        }
    }



    public RDBS(Point g, Point h, G2Point hatG) {
        this.g = g;
        this.h = h;
        this.hatG = hatG;
    }

    public Point genPedCom(Scalar v, Scalar r){
        Point vG = this.g.mul(v);
        Point rH = this.h.mul(r);
        Point C = vG.add(rH);
        return C;
    }

    public KeyPair keyGen(){
        Scalar x = Scalar.random();

        G2Point X = G2.ECTwistMul(hatG, x.toBigInt());
        return new KeyPair(x, X);
    }

    public AuthInfo authCom(Scalar v, Scalar x, Scalar r){

        Point vG = this.g.mul(v);
        Point rH = this.h.mul(r);
        Point C = vG.add(rH);

        CM cm = new CM(C);

        Scalar s = Scalar.random();
        Scalar sInv = s.inv();

        Point xC = C.mul(x);
        Point Z = this.g.add(xC).mul(sInv);

        Point S = this.g.mul(s);

        G2Point hatS = G2.ECTwistMul(this.hatG, s.toBigInt());

        Point xH = this.h.mul(x);
        Point T = xH.mul(sInv);
        Sig sig = new Sig(Z, S, T, hatS);
        return new AuthInfo(cm, sig);
    }

    public boolean vfCom(CM cm, Scalar v, Scalar r){


        Point vG = this.g.mul(v);
        Point rH = this.h.mul(r);
        Point C = vG.add(rH);

        if (!cm.C.equals(C)){
            return false;
        }

        return true;

    }

    public boolean vfAuth(CM cm, Sig sig, G2Point X) throws Exception {

        G1Point[] e_l = new G1Point[]{sig.Z.neg().p, this.g.p, cm.C.p};
        G2Point[] e_r = new G2Point[]{sig.hatS, this.hatG, X};
        boolean result =  pairing(e_l, e_r);
        if (!result){
            return false;
        }

        e_l = new G1Point[]{this.g.neg().p, sig.S.p};
        e_r = new G2Point[]{sig.hatS, this.hatG};
        result =  pairing(e_l, e_r);
        if (!result){
            return false;
        }

        e_l = new G1Point[]{sig.T.neg().p, this.h.p};
        e_r = new G2Point[]{sig.hatS, X};
        result =  pairing(e_l, e_r);
        if (!result){
            return false;
        }
        return true;
    }

    public AuthInfo rdmAC(CM cm, Sig sig, Scalar r){
        Scalar s = Scalar.random();
        Scalar sInv = s.inv();

        Point C = cm.C.add(this.h.mul(r));
        CM cm_ = new CM(C);

        Point rT = sig.T.mul(r);
        Point Z = sig.Z.add(rT).mul(sInv);
        Point S = sig.S.mul(s);
        G2Point hatS = G2.ECTwistMul(sig.hatS, s.toBigInt());
        Point T = sig.T.mul(sInv);
        Sig sig_ = new Sig(Z, S, T, hatS);
        return new AuthInfo(cm_, sig_);
    }

    public AuthInfo updAC(CM cm, Scalar x){

        Scalar s = Scalar.random();
        Scalar sInv = s.inv();

        Point xC = cm.C.mul(x);
        Point Z = this.g.add(xC).mul(sInv);

        Point S = this.g.mul(s);

        G2Point hatS = G2.ECTwistMul(this.hatG, s.toBigInt());

        Point xH = this.h.mul(x);
        Point T = xH.mul(sInv);
        Sig sig = new Sig(Z, S, T, hatS);
        return  new AuthInfo(cm, sig);
    }

    public boolean vfUpd(CM cm, Point amt, CM cm_, Sig sig, G2Point X) throws Exception {


        Point C_ = cm.C.add(amt);

        if (!C_.equals(cm_.C)){
            return false;
        }

        if(vfAuth(cm_, sig, X)){
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

        public AuthInfo(AuthInfo other){
            this.cm = new CM(other.cm.C);
            this.sig = new Sig(other.sig.Z, other.sig.S, other.sig.T, other.sig.hatS );
        }

        @Override
        public String toString(){
            return cm.C.toString()
                    + sig.Z.toString()
                    + sig.S.toString()
                    + sig.T.toString()
                    + sig.hatS.toString();
        }
    }

    public static class KeyPair{
        public Scalar x;
        public G2Point X;

        public KeyPair(Scalar x, G2Point x1) {
            this.x = x;
            X = x1;
        }
    }

    public static class CM{
        public Point C;

        public CM(Point c) {
            C = c;
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

