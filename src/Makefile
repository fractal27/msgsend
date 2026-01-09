# Makefile for source directory
include ../make/src.mk

all: release

.PHONY: release debug clean

# $(PATH_TO_HERBE)/herbe:
# 	$(MAKE) -C '${PATH_TO_HERBE}'

../obj/%.o: %.c
	$(CC) -c ${CPPFLAGS} ${CFLAGS} $< -o $@

${RELEASE_DIR}/client: ${OBJECTS_CLIENT} ${OBJECTS_SERVER}
	$(LD) ${LDFLAGS} ${OBJECTS_CLIENT} -o ${RELEASE_DIR}/client ${LIBS}
	strip ${RELEASE_DIR}/client

${RELEASE_DIR}/server: ${OBJECTS_SERVER} ${OBJECTS_SERVER}
	$(LD) ${LDFLAGS} ${OBJECTS_SERVER} -o ${RELEASE_DIR}/server ${LIBS}
	strip ${RELEASE_DIR}/server


release:  ${RELEASE_TARGETS}

debug: ${SOURCES}
	$(CC) ${DEBUG_CFLAGS} ${SOURCES_SERVER} -o ${DEBUG_DIR}/server ${LIBS}
	$(CC) ${DEBUG_CFLAGS} ${SOURCES_CLIENT} -o ${DEBUG_DIR}/client ${LIBS}

clean:
	rm -f $(RELEASE_DIR)/client $(RELEASE_DIR)/server
