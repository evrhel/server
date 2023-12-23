AUTOMAKE_OPTIONS = foreign subdir-objects

bin_PROGRAMS = server
server_SOURCES = src/http.c src/resource.c src/server.c src/sqlite3.c src/stream.c src/user.c src/util.c

server_LDADD = -L/usr/local/lib -lssl -lcrypto
server_CFLAGS = -Wall -std=c99 -g3