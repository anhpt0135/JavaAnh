lib=libhello.so
src=HelloJNI.c
CFLAGS=-I. -I/usr/lib/jvm/default-java/include -I/usr/lib/jvm/default-java/include/linux -fPIC

all:$(lib)
	
$(lib):HelloJNI.h obj
	gcc -shared $(CFLAG) obj -o $@ 

HelloJNI.h : ../bin/HelloJNI.class
	javac -h . ../src/HelloJNI.java

obj:$(src)
	gcc $(CFLAGS) -c -o $@ $^
	
clean:
	rm -f HelloJNI.h HelloJNI.o hello.so
	
