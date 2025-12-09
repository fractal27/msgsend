# Makefile configuration

# PATH_TO_HERBE=$(PWD)/herbe
SOURCES = client.c server.c gpg-util.c
LIBS = -L ./lib -lgpgme
CFLAGS=-Wall -O2 -DDEBUG -ggdb


