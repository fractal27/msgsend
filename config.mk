# Makefile configuration

# PATH_TO_HERBE=$(PWD)/herbe
SOURCES = client.c server.c gpg-util.c
LIBS = `pkgconf --libs gpgme`#`pkgconf --libs openssl`
CFLAGS=-Wall -O2 -DDEBUG -ggdb


