package lighthub;


import accio.RSUC;
import encryption.MyECDSA;
import encryption.bulletproof.*;
import global.Global;

import java.math.BigInteger;

public class LightHubMain {

    public static void main(String[] args) throws Exception {

        Scalar payerV = new Scalar(new BigInteger("1004523532450"));
        Scalar payeeV = new Scalar(new BigInteger("1004523532450"));
        Scalar hubV = new Scalar(new BigInteger("1004523532450"));

        User payer = new User(payerV);
        User payee = new User(payeeV);
        Hub hubLeft = new Hub(hubV);
        Hub hubRight = new Hub(hubV);

        RDBS rdbs = new RDBS(Global.g, Global.h, Global.hatG);
        RDBS.KeyPair keyPair = rdbs.keyGen();
        hubLeft.setKeyPair(keyPair);

        hubRight.setKeyPair(keyPair);

        Scalar rLeft = Scalar.random();
        UserHubChannel payerHub = new UserHubChannel(payer, hubLeft);
        payerHub.setRDBS(rdbs);
        RDBS.AuthInfo authInfoLeft  = payerHub.blindChannel(rLeft);

        Scalar rRight = Scalar.random();
        UserHubChannel payeeHub = new UserHubChannel(payee, hubLeft);
        payeeHub.setRDBS(rdbs);
        RDBS.AuthInfo authInfoRight  = payeeHub.blindChannel(rRight);

        // start pay
        Scalar amt_r = Scalar.random();
        Scalar value = new Scalar(new BigInteger("13432"));
        Point blind_amt = rdbs.genPedCom(value, amt_r);

        Scalar realValue = payerHub.cleanValue();
        Scalar prove_v = realValue.sub(value);
        Scalar prove_r = rLeft.sub(amt_r);

        PedersenCommitment pc = new PedersenCommitment();       // 含基点 g, h
        BulletproofGens gens  = new BulletproofGens(Global.VALUEBITS, 1);

        Transcript tsProver = new Transcript("BP".getBytes());
        RangeProof proof = RangeProof.prove(prove_v.toLong(), prove_r, Global.VALUEBITS, pc, gens, tsProver);

        Point preValue = payerHub.getRealValuePoint();

        Point commitment_ = authInfoLeft.cm.C.add(blind_amt.neg()).add(preValue.neg());

        // ----- Verify 计时 -----
        Transcript tsVer = new Transcript("BP".getBytes());
        boolean ok = proof.verify(commitment_, Global.VALUEBITS, pc, gens, tsVer);
        System.out.println("ok1 = " + ok);

        // hub check value and sign new state
        boolean checkLeft = rdbs.vfAuth(authInfoLeft.cm, authInfoLeft.sig, keyPair.X);
        boolean checkRight = rdbs.vfAuth(authInfoRight.cm, authInfoRight.sig, keyPair.X);

        authInfoLeft = payerHub.sendValue(blind_amt);
        authInfoRight = payeeHub.receiveValue(blind_amt);

        // payer check
        ok = payerHub.checkSendValue(blind_amt);
        System.out.println("ok2 = " + ok);

        ok = payeeHub.checkReceiveValue(blind_amt);
        System.out.println("ok3 = " + ok);

        // payee check and rand
        ok = payeeHub.checkReceiveValue(blind_amt);
        System.out.println("ok4 = " + ok);

        authInfoRight = payeeHub.randChannel();
    }
}
