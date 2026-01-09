# Makefile configuration

CC := clang
LD := clang

SOURCES_CLIENT   := client.c gpg-util.c client_main.c shared.c
SOURCES_SERVER   := server.c server_main.c shared.c
OBJ_DIR          := ../obj
BIN_DIR          := ../bin
DEBUG_DIR        := ../debug
RELEASE_DIR      := ../bin

OBJECTS_CLIENT  := ${OBJ_DIR}/client.o ${OBJ_DIR}/gpg-util.o ${OBJ_DIR}/client_main.o
OBJECTS_SERVER  := ${OBJ_DIR}/server.o ${OBJ_DIR}/server_main.o
DEBUG_TARGETS   := ${DEBUG_DIR}/server ${DEBUG_DIR}/client
RELEASE_TARGETS := ${RELEASE_DIR}/server ${RELEASE_DIR}/client

OPTIMIZATIONS   := -march=native -O3

LIBS          := -lgpgme -lc
CFLAGS        := -I ../include -D_FORTIFY_SOURCE ${OPTIMIZATIONS}
LDFLAGS 	  := ${CFLAGS}
DEBUG_CFLAGS  := -rdynamic -no-pie -Wall -O2 -DDEBUG -ggdb -I ../include -D_FORTIFY_SOURCE -Wno-unused

