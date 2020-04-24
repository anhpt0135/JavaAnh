
public class SSLClientBT {
   static {
      System.loadLibrary("SSLClientBT");
   }
   // A native method that receives nothing and returns void
   private native String sendSecuredCommandBT(String ipAddress, String port, String psk, String pskIdentity, String command);
 
   public static void main(String[] args) {
	  SSLClientBT inst = new SSLClientBT();
      //String result = inst.sendSecuredCommandBT("127.0.0.1", "4433", "46A08A57073DB2AA6BD3F69A75EA694D", "dnh4ch446jgj17v6eqmjc104rj", "get_udid");  // invoke the native method
      String result = inst.sendSecuredCommandBT("127.0.0.1", "4433", "", "", "get_udid");
      System.out.println(result);
   }
}
