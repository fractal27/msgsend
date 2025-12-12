# Makefile for source directory
include "../make/src.mk"

all: release

# $(PATH_TO_HERBE)/herbe:
# 	$(MAKE) -C '${PATH_TO_HERBE}'

../obj/%.o: %.c
	$(CC) -c ${CPPFLAGS} ${CFLAGS} $< -o $@ #${LIBS}

${RELEASE_DIR}/client: ${OBJECTS_CLIENT} ${OBJECTS_SERVER}
	$(LD) ${LDFLAGS} ${OBJECTS_CLIENT} -o ${RELEASE_DIR}/client ${LIBS}

${RELEASE_DIR}/server: ${OBJECTS_SERVER} ${OBJECTS_SERVER}
	$(LD) ${LDFLAGS} ${OBJECTS_SERVER} -o ${RELEASE_DIR}/server ${LIBS}

release:  ${RELEASE_TARGETS}

debug: ${SOURCES}
	$(CC) ${DEBUG_CFLAGS} server.c -o server ${LIBS}
	$(CC) ${DEBUG_CFLAGS} client.c gpg-util.c -o client ${LIBS}

clean:
	rm -f client server
