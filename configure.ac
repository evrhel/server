AC_INIT([server], [1.0])

AC_CONFIG_SRCDIR([src])
AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE

AC_PROG_CC

SOURCE_URL="https://www.sqlite.org/2019/sqlite-amalgamation-3290000.zip"

wget -O sqlite.zip $SOURCE_URL

# move sqlite3.c and sqlite3.h to src and delete the rest
unzip sqlite.zip
mv sqlite-amalgamation-3290000/sqlite3.c src/sqlite3.c
mv sqlite-amalgamation-3290000/sqlite3.h src/sqlite3.h
rm -rf sqlite-amalgamation-3290000
rm sqlite.zip

#PKG_CHECK_MODULES([SQLITE], [sqlite3 >= 3.0])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT