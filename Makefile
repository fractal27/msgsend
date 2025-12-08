include config.mk

all: client server

$(PATH_TO_HERBE)/herbe:
	$(MAKE) -C '${PATH_TO_HERBE}'

client: ${SOURCES}
	@#$(CC) -DPATH_TO_HERBE="${PATH_TO_HERBE}" ${CFLAGS} client.c -o client ${LIBS}
	$(CC) ${CFLAGS} -fsanitize=address -fPIC -g client.c gpg-util.c -o client ${LIBS}

server: ${SOURCES}
	$(CC) ${CFLAGS} serverv1.c -o server ${LIBS}

clean:
	rm -f client server
