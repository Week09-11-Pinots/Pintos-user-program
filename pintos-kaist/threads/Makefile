include ../Makefile.kernel

.PHONY: thread
thread:
	make clean && \
	make -j && \
	cd ./build && \
	make check

.PHONY: log
log:
	make clean && \
	make -j CFLAGS="-fno-stack-protector -DDEBUG_LOG"