GCC := gcc -std=c99 -Wall -g3 -L/usr/local/lib -lcrypto -lssl

all: server

server:
	$(GCC) -o server src/server.c

nossl:
	$(GCC) -D NO_OPENSSL -o server src/server.c

user:
	$(GCC) -D _BUILD_USER_UTIL_ -o userutil src/user.c

clean:
	rm -f *.o
	rm -f server
	rm -f userutil