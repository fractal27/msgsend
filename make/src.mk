# Makefile configuration

CC := clang
LD := clang

SOURCES_CLIENT   := client.c gpg-util.c
SOURCES_SERVER   := server.c
OBJ_DIR          := ../obj
BIN_DIR          := ../bin
DEBUG_DIR        := ../debug
RELEASE_DIR      := ../bin

OBJECTS_CLIENT  := $(OBJ_DIR)/client.o $(OBJ_DIR)/gpg-util.o
OBJECTS_SERVER  := $(OBJ_DIR)/server.o
DEBUG_TARGETS   := ${DEBUG_DIR}/server ${DEBUG_DIR}/client
RELEASE_TARGETS := ${RELEASE_DIR}/server ${RELEASE_DIR}/client

LIBS          := -L ../lib -lgpgme -lc
CFLAGS        := -O2 -I ../include -D_FORTIFY_SOURCE
DEBUG_CFLAGS  := -Wall -O2 -DDEBUG -ggdb -I ../include -D_FORTIFY_SOURCE -Wno-unused

