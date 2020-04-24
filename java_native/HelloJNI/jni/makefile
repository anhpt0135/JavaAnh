target=libhello.so
CFLAGS=-I. -I/usr/lib/jvm/java-11-oracle/include -I/usr/lib/jvm/java-11-oracle/include/linux
CFLAGS +=-I./mbedtls-2.13.0/include
MBEDLIBDIR=./mbedtls-2.13.0/library/
src=$(wildcard *.c)
obj=$(src:.c=.o)

all:$(target)
	
$(target):HelloJNI.h mbedlib $(obj)	
	gcc -shared $(CFLAGS) -o $@ -Wl,--whole-archive $(MBEDLIBDIR)*.a -Wl,--no-whole-archive $(obj)

HelloJNI.h:
	javac -h . ../src/HelloJNI.java

mbedlib:
	$(MAKE) -C mbedtls-2.13.0/
	
%.o:%.c
	gcc -c -fPIC $(CFLAGS) -o $@ $^ 
	
clean:
	rm -f HelloJNI.h HelloJNI.o *.so *.so.* *.a
	$(MAKE) -C mbedtls-2.13.0/ clean
	
