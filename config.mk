# Makefile configuration

# PATH_TO_HERBE=$(PWD)/herbe
SOURCES = client.c server.c gpg-util.c
LIBS = -L ./lib -lgpgme
CFLAGS=-O2 -I ./include
DFLAGS=-Wall -Werror -O2 -DDEBUG -ggdb -I ./include

