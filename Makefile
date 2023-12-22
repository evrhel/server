GCC := gcc -std=c99 -Wall -g3 -Ithirdparty/sqlite
LINK := gcc -std=c99 -Wall -g3 -L/usr/local/lib -lcrypto -lssl

all: server

server: server.o user.o http.o resource.o stream.o sqlite3.o
	$(LINK) -o server server.o user.o http.o resource.o stream.o sqlite3.o

server.o:
	$(GCC) -o server.o -c src/server.c

user.o:
	$(GCC) -o user.o -c src/user.c

http.o:
	$(GCC) -o http.o -c src/http.c

resource.o:
	$(GCC) -o resource.o -c src/resource.c

stream.o:
	$(GCC) -o stream.o -c src/stream.c

sqlite3.o:
	$(GCC) -o sqlite3.o -c thirdparty/sqlite/sqlite3.c

.PHONY: clean
clean:
	rm -f *.o
	rm -f server
