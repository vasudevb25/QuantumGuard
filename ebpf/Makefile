CLANG := clang
CC := gcc

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS := $(shell pkg-config --libs libbpf)

all: probes.o probes.skel.h loader

probes.o: probes.c
	$(CLANG) -O2 -g -target bpf \
	-D__TARGET_ARCH_x86 \
	-I. \
	-c probes.c -o probes.o

probes.skel.h: probes.o
	bpftool gen skeleton probes.o > probes.skel.h

loader: loader.c probes.skel.h
	$(CC) loader.c \
	-o loader \
	$(LIBBPF_CFLAGS) \
	$(LIBBPF_LIBS)

clean:
	rm -f loader probes.o probes.skel.h