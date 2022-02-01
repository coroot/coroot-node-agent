FROM alpine:3.13

RUN apk add llvm clang libbpf-dev linux-headers

COPY ebpf/* /tmp/
WORKDIR /tmp

RUN clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -D__KERNEL=416 -c ebpf.c -o ebpf416.o && llvm-strip --strip-debug ebpf416.o
RUN clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -D__KERNEL=420 -c ebpf.c -o ebpf420.o && llvm-strip --strip-debug ebpf420.o
RUN clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -D__KERNEL=506 -c ebpf.c -o ebpf506.o && llvm-strip --strip-debug ebpf506.o

RUN echo -en '// generated - do not edit\npackage ebpftracer\nvar ebpfProg = []struct{v string; p []byte}{\n' > ebpf.go \
	&& echo -en '\t{"v5.6", []byte("' >> ebpf.go && hexdump -v -e '"\x" 1/1 "%02x"' ebpf506.o >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t{"v4.20", []byte("' >> ebpf.go && hexdump -v -e '"\x" 1/1 "%02x"' ebpf420.o >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t{"v4.16", []byte("' >> ebpf.go && hexdump -v -e '"\x" 1/1 "%02x"' ebpf416.o >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '}\n'>> ebpf.go
