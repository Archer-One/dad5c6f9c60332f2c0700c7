package accio;

import encryption.bulletproof.Scalar;
import accio.entity.Hub;
import accio.entity.User;

import static encryption.MyECDSA.verify;

public class PayerHubChannel {
    public Integer state=0;
    public User payer;
    public Hub hub;

    public Scalar allValue;
    public PayerHubChannel(User payer, Hub hub) {
        this.state = state;
        this.payer = payer;
        this.hub = hub;
        this.allValue = payer.value.add(hub.value);
    }

    public boolean channelCheck(byte[] hubSig, byte[] payerSig, String message){
        boolean result1 = verify(hub.ecdsaPk, message.getBytes(), hubSig);
        boolean result2 = verify(payer.ecdsaPk, message.getBytes(), payerSig);
        if (result1 &  result2){
            return true;
        }else {
            return false;
        }
    }

    public boolean payment(Scalar amount){
        if (amount.toBigInt().compareTo(payer.value.toBigInt()) <1){
//            payer.value = payer.value.sub(amount);
//            hub.value = hub.value.add(amount);

            payer.value.sub(amount);
            hub.value.add(amount);
            state = state +1;
            return true;
        }
        return false;
    }


    @Override
    public String toString(){
        return "ChannelState{" +
                "state=" + state +
                ", user=" + payer.value + new String(payer.ecdsaPk)  +
                ", hub=" + hub.value + new String(hub.ecdsaPk)  +
                '}';
    }


}
