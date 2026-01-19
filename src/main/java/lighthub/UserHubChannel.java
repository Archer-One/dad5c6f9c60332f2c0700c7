package lighthub;


import encryption.MySha256;
import encryption.bulletproof.Point;
import encryption.bulletproof.Scalar;
import org.aion.tetryon.Pairing;
import tools.MyUtils;
import java.math.BigInteger;

public class UserHubChannel {
    public BigInteger state= BigInteger.ZERO;
    public User user;
    public Hub hub;

    public Scalar value;
    public Scalar allValue;

    public Point statePoint;

    public RDBS rdbs;

    public RDBS.AuthInfo authInfo;
    public RDBS.AuthInfo preAuthInfo;

    public BigInteger id;
    public UserHubChannel(User user, Hub hub) {
        this.user = user;
        this.hub = hub;
        this.allValue = user.value.add(hub.value);

        this.id = MySha256.sha256First128BitsBC(this.toString().getBytes());

    }

    public void setRDBS(RDBS rdbs) {
        this.rdbs = rdbs;
        this.fixStatePoint();
    }

    public RDBS.AuthInfo blindChannel(Scalar r){

        BigInteger shiftResult = concatThree(this.id, this.state, user.value.toBigInt());
        this.value = new Scalar(shiftResult);
        RDBS.AuthInfo authInfo = rdbs.authCom(this.value, hub.keyPair.x, r);
        this.authInfo = authInfo;
        return authInfo;
    }

    public Scalar cleanValue(){
        BigInteger mask64 = new BigInteger("FFFFFFFFFFFFFFFF", 16);

        BigInteger realValue = this.value.toBigInt().and(mask64);
        return new Scalar(realValue);
    }

    public BigInteger constructPayment(BigInteger big64) {
        // 使用掩码确保在指定位数内
        BigInteger big128 = this.id;
        BigInteger big32 = this.state;

        BigInteger mask128 = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
        BigInteger mask32 = new BigInteger("FFFFFFFF", 16);
        BigInteger mask64 = new BigInteger("FFFFFFFFFFFFFFFF", 16);

        BigInteger safe128 = big128.and(mask128);
        BigInteger safe32 = big32.and(mask32);
        BigInteger safe64 = big64.and(mask64);

        // 使用String.format格式化固定长度
        String hex128 = String.format("%032x", safe128);
        String hex32 = String.format("%08x", safe32);
        String hex64 = String.format("%016x", safe64);

        // 拼接
        String combined = hex128 + hex32 + hex64;
        return new BigInteger(combined, 16);
    }

    public Point getRealValuePoint(){
        // get g^{id || state || 00000 }
       BigInteger preValue = constructPayment(BigInteger.ZERO);
        Point result = rdbs.g.mul(new Scalar(preValue));
        return result;
    }

    public static BigInteger concatThree(BigInteger big128, BigInteger big32, BigInteger big64) {
        // 使用掩码确保在指定位数内
        BigInteger mask128 = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
        BigInteger mask32 = new BigInteger("FFFFFFFF", 16);
        BigInteger mask64 = new BigInteger("FFFFFFFFFFFFFFFF", 16);

        BigInteger safe128 = big128.and(mask128);
        BigInteger safe32 = big32.and(mask32);
        BigInteger safe64 = big64.and(mask64);

        // 使用String.format格式化固定长度
        String hex128 = String.format("%032x", safe128);
        String hex32 = String.format("%08x", safe32);
        String hex64 = String.format("%016x", safe64);

        // 拼接
        String combined = hex128 + hex32 + hex64;
        return new BigInteger(combined, 16);
    }


    public void fixStatePoint(){
        BigInteger mask32 = new BigInteger("FFFFFFFF", 16);
        BigInteger mask64 = new BigInteger("FFFFFFFFFFFFFFFF", 16);

        BigInteger safe32 = BigInteger.ONE.and(mask32);
        BigInteger safe64 = BigInteger.ZERO.and(mask64);

        // 使用String.format格式化固定长度
        String hex32 = String.format("%08x", safe32);
        String hex64 = String.format("%016x", safe64);

        // 拼接
        String combined =  hex32 + hex64;
        Scalar stateValue = new Scalar( new BigInteger(combined, 16));
        this.statePoint = rdbs.g.mul(stateValue);
    }

    public RDBS.AuthInfo sendValue(Point amt){
        this.preAuthInfo = new RDBS.AuthInfo(this.authInfo) ;
        this.authInfo.cm.C = this.authInfo.cm.C.add(amt.neg()).add(this.statePoint); // state add 1
        this.authInfo = rdbs.updAC(this.authInfo.cm, this.hub.keyPair.x);
        return authInfo;
    }

    public boolean checkSendValue(Point amt) throws Exception {
        Point amt_ = amt.add(this.statePoint.neg());
        return this.rdbs.vfUpd(this.preAuthInfo.cm, amt_.neg(), this.authInfo.cm, this.authInfo.sig, this.hub.keyPair.X);
    }

    public RDBS.AuthInfo randChannel(){
        this.preAuthInfo = new RDBS.AuthInfo(this.authInfo) ;
        this.authInfo = rdbs.rdmAC(authInfo.cm, authInfo.sig, Scalar.random());
        return authInfo;
    }

    public RDBS.AuthInfo receiveValue(Point amt){
        this.preAuthInfo = new RDBS.AuthInfo(this.authInfo) ;
        this.authInfo.cm.C = this.authInfo.cm.C.add(amt);
        this.authInfo = rdbs.updAC(this.authInfo.cm, this.hub.keyPair.x);
        return authInfo;
    }

    public boolean checkReceiveValue(Point amt) throws Exception {
        return this.rdbs.vfUpd(this.preAuthInfo.cm, amt, this.authInfo.cm, this.authInfo.sig, this.hub.keyPair.X);
    }

    @Override
    public String toString(){
        return "ChannelState{" +
                "state=" + state +
                ", user=" + user.value + new String(user.ecdsaPk)  +
                ", hub=" + hub.value + new String(hub.ecdsaPk)  +
                '}';
    }
}
