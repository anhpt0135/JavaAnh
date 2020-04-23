
public class HelloJNI {
   static {
      System.loadLibrary("hello"); // hello.dll (Windows) or libhello.so (Unixes)
   }
   // A native method that receives nothing and returns void
   private native String sayHello(String msg, int value);
 
   public static void main(String[] args) {
	  HelloJNI inst = new HelloJNI();
      String result = inst.sayHello("Hello from java\n", 5);  // invoke the native method
      System.out.println(result);
   }
}
