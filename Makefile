include make/root.mk

${OBJECTS_FROM_ROOT} ${TARGETS_FROM_ROOT}: ${SOURCES_FROM_ROOT}
	$(MAKE) -C src release

debug: ${SOURCES_FROM_ROOT}
	$(MAKE) -C src debug

clean:
	rm -f client server

.PHONY: clean debug
