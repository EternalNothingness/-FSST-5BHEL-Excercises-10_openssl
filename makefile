openssl : openssl.o
	gcc openssl.o -o openssl -lcrypto

openssl.o : openssl.c
	gcc -c openssl.c -o openssl.o -g

clean :
	rm -f openssl.o
