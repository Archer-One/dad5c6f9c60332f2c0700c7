package accio;

import encryption.bulletproof.Scalar;
import accio.entity.Hub;
import accio.entity.User;

import static encryption.MyECDSA.verify;

public class PayeeHubChannel {
    public Integer state=0;
    public User payee;
    public Hub hub;

    public Scalar allValue;

    public RSUC rsuc;

    public RSUC.AuthInfo authInfo;
    public PayeeHubChannel(User payee, Hub hub) {
        this.payee = payee;
        this.hub = hub;
        this.allValue = payee.value.add(hub.value);
    }

    public void setRsuc(RSUC rsuc) {
        this.rsuc = rsuc;
    }

    public RSUC.AuthInfo blindChannel(Scalar r){
        RSUC.AuthInfo authInfo = rsuc.authCom(payee.value, hub.keyPair.x0, hub.keyPair.x1, r);
        this.authInfo = authInfo;
        return authInfo;
    }

    public boolean channelCheck(byte[] hubSig, byte[] payeeSig, String message){
        boolean result1 = verify(hub.ecdsaPk, message.getBytes(), hubSig);
        boolean result2 = verify(payee.ecdsaPk, message.getBytes(), payeeSig);
        if (result1 &  result2){
            return true;
        }else {
            return false;
        }
    }

    public boolean payment(Scalar amount){
        if (amount.toBigInt().compareTo(payee.value.toBigInt()) <1){
            payee.value = payee.value.sub(amount);
            hub.value = hub.value.add(amount);
            state = state +1;
            return true;
        }
        return false;
    }


    @Override
    public String toString(){
        return "ChannelState{" +
                "state=" + state +
                ", user=" + payee.value + new String(payee.ecdsaPk)  +
                ", hub=" + hub.value + new String(hub.ecdsaPk)  +
                ", authInfo =" + authInfo.toString() +
                '}';
    }


}
