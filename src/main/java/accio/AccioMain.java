package accio;

import encryption.MyECDSA;
import encryption.bulletproof.Scalar;
import accio.entity.Hub;
import accio.entity.User;
import global.Global;

import java.math.BigInteger;

public class AccioMain {
    public static void main(String[] args) throws Exception {
        Scalar payerV = new Scalar(new BigInteger("100000000000000"));

        User payer = new User(payerV);
        Hub hubLeft = new Hub(new Scalar(BigInteger.ZERO));

        PayerHubChannel payerHub = new PayerHubChannel(payer, hubLeft);

        //open left channel
        String msg = payerHub.toString();
        byte[] payerSig = MyECDSA.sign(payer.ecdsaSk, msg.getBytes());
        byte[] hubSig = MyECDSA.sign(hubLeft.ecdsaSk, msg.getBytes());
        boolean openResult = payerHub.channelCheck(hubSig, payerSig, msg);
        if (openResult){
            System.out.println("left channel open successfully");
        }else {
            System.out.println("left channel open unsuccessfully");
        }



        Scalar HubV = new Scalar(new BigInteger("100000000000000"));
        User payee = new User(new Scalar(BigInteger.ZERO));
        Hub hubRight = new Hub(HubV);
        RSUC rsuc = new RSUC(Global.g, Global.h, Global.hatG);
        RSUC.KeyPair keyPair = rsuc.keyGen();
        hubRight.setKeyPair(keyPair);

        PayeeHubChannel payeeHub = new PayeeHubChannel(payee, hubRight);
        payeeHub.setRsuc(rsuc);
        Scalar r = Scalar.random();

        RSUC.AuthInfo authInfo = payeeHub.blindChannel(r);
        boolean cmCheck = rsuc.vfCom(authInfo.cm, payeeHub.payee.value ,r);
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

        String msg_ = payeeHub.toString();
        byte[] payeeSig = MyECDSA.sign(payee.ecdsaSk, msg_.getBytes());
        byte[] hubSig_ = MyECDSA.sign(hubRight.ecdsaSk, msg_.getBytes());
        boolean openResult_ = payeeHub.channelCheck(hubSig_, payeeSig, msg_);
        if (openResult_){
            System.out.println("right channel open successfully");
        }else {
            System.out.println("right channel open unsuccessfully");
        }

        //start pay
        // blind right

        Scalar amount = new Scalar(new BigInteger("234234234"));

        Scalar r_ = Scalar.random();
        RSUC.AuthInfo authInfo_ = rsuc.rdmAC(authInfo.cm, authInfo.sig, r_);
        boolean authCheck_ = rsuc.vfAuth(authInfo.cm, authInfo.sig, keyPair.X0, keyPair.X1);
        if (!authCheck_){
            System.out.println("blinded Auth check error!");
        }else {
            System.out.println("blinded Auth check success!");
        }

        boolean paymentResult = payerHub.payment(amount);
        if (!paymentResult){
            System.out.println("invalid payment amount");
        }else {
            msg = payerHub.toString();
            payerSig = MyECDSA.sign(payer.ecdsaSk, msg.getBytes());
            hubSig = MyECDSA.sign(hubLeft.ecdsaSk, msg.getBytes());
            paymentResult = payerHub.channelCheck(hubSig, payerSig, msg);
            if (paymentResult){
                System.out.println("left channel pay successfully");
            }else {
                System.out.println("left channel pay unsuccessfully");
            }
        }


        // hub check
        authCheck_ = rsuc.vfAuth(authInfo.cm, authInfo.sig, keyPair.X0, keyPair.X1);
        if (!authCheck_){
            System.out.println("blinded Auth check error!");
        }else {
            System.out.println("blinded Auth check success!");
        }

        // hub update
        RSUC.AuthInfo authInfo1 = rsuc.updAC(authInfo_.cm, amount, keyPair.x0, keyPair.x1);

        // payer check
        boolean authInfo1Check_ = rsuc.vfUpd(authInfo_.cm, amount, authInfo1.cm, authInfo1.sig, keyPair.X0, keyPair.X1);
        if (!authInfo1Check_){
            System.out.println("updated Auth check error!");
        }else {
            System.out.println("updated Auth check success!");
        }

        // payee check
        authInfo1Check_ = rsuc.vfUpd(authInfo_.cm, amount, authInfo1.cm, authInfo1.sig, keyPair.X0, keyPair.X1);
        if (!authInfo1Check_){
            System.out.println("updated Auth check error!");
        }else {
            System.out.println("updated Auth check success!");
        }

        // payee blind
        authInfo_ = rsuc.rdmAC(authInfo.cm, authInfo.sig, r_);
    }
}
