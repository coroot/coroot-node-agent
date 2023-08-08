FROM alpine:3.13

RUN apk add llvm clang libbpf-dev linux-headers

COPY ebpf /tmp/ebpf
WORKDIR /tmp/ebpf

RUN clang -g -O2 -target bpf -D__KERNEL_FROM=416 -D__TARGET_ARCH_x86 -c ebpf.c -o ebpf416x86.o && llvm-strip --strip-debug ebpf416x86.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=420 -D__TARGET_ARCH_x86 -c ebpf.c -o ebpf420x86.o && llvm-strip --strip-debug ebpf420x86.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=506 -D__TARGET_ARCH_x86 -c ebpf.c -o ebpf506x86.o && llvm-strip --strip-debug ebpf506x86.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=512 -D__TARGET_ARCH_x86 -c ebpf.c -o ebpf512x86.o && llvm-strip --strip-debug ebpf512x86.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=416 -D__TARGET_ARCH_arm64 -c ebpf.c -o ebpf416arm64.o && llvm-strip --strip-debug ebpf416arm64.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=420 -D__TARGET_ARCH_arm64 -c ebpf.c -o ebpf420arm64.o && llvm-strip --strip-debug ebpf420arm64.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=506 -D__TARGET_ARCH_arm64 -c ebpf.c -o ebpf506arm64.o && llvm-strip --strip-debug ebpf506arm64.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=512 -D__TARGET_ARCH_arm64 -c ebpf.c -o ebpf512arm64.o && llvm-strip --strip-debug ebpf512arm64.o

RUN echo -en '// generated - do not edit\npackage ebpftracer\nvar ebpfProg = map[string][]struct{v string; p []byte}{\n' > ebpf.go \
	&& echo -en '\t"amd64": {\n' >> ebpf.go \
	&& echo -en '\t\t{"v5.12", []byte("' >> ebpf.go && hexdump -v -e '"\x" 1/1 "%02x"' ebpf512x86.o >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"v5.6", []byte("' >> ebpf.go && hexdump -v -e '"\x" 1/1 "%02x"' ebpf506x86.o >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"v4.20", []byte("' >> ebpf.go && hexdump -v -e '"\x" 1/1 "%02x"' ebpf420x86.o >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"v4.16", []byte("' >> ebpf.go && hexdump -v -e '"\x" 1/1 "%02x"' ebpf416x86.o >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t},\n'>> ebpf.go \
	&& echo -en '\t"arm64": {\n' >> ebpf.go \
	&& echo -en '\t\t{"v5.12", []byte("' >> ebpf.go && hexdump -v -e '"\x" 1/1 "%02x"' ebpf512arm64.o >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"v5.6", []byte("' >> ebpf.go && hexdump -v -e '"\x" 1/1 "%02x"' ebpf506arm64.o >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"v4.20", []byte("' >> ebpf.go && hexdump -v -e '"\x" 1/1 "%02x"' ebpf420arm64.o >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"v4.16", []byte("' >> ebpf.go && hexdump -v -e '"\x" 1/1 "%02x"' ebpf416arm64.o >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t},\n'>> ebpf.go \
	&& echo -en '}\n'>> ebpf.go
