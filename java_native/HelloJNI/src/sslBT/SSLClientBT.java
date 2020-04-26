package sslBT;

public class SSLClientBT {
	static {
		System.loadLibrary("SSLClientBT");
	}

	// A native method that receives nothing and returns void
	private static native String sendSecuredCommandBT(String ipAddress, String port, String psk, String pskIdentity,
			String command, int timeout);

	public String SendcommandBT(String ip, String port, String psk, String pskID, String command, int timeout) {		
		return sendSecuredCommandBT(ip, port, psk, pskID, command, timeout);
	}
	/*
	 * public static void main(String[] args) { SSLClientBT inst = new
	 * SSLClientBT(); String result = inst.sendSecuredCommandBT("192.168.1.43",
	 * "4433", "EB3C53C3E331E589B9B3C7F1D73AA039", "3mguu97dd5vp4f37h3dbsvb3bp",
	 * "get_udid", 1000); // invoke the native method // String result =
	 * inst.sendSecuredCommandBT("127.0.0.1", "4433", "", "", // "get_udid");
	 * System.out.println(result); }
	 */
}
