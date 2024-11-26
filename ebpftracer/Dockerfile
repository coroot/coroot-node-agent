FROM alpine:3.14

RUN apk add llvm clang libbpf-dev linux-headers

COPY ebpf /tmp/ebpf
WORKDIR /tmp/ebpf

RUN clang -g -O2 -target bpf -D__KERNEL_FROM=416 -D__TARGET_ARCH_x86 -c ebpf.c -o ebpf416x86.o && llvm-strip --strip-debug ebpf416x86.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=420 -D__TARGET_ARCH_x86 -c ebpf.c -o ebpf420x86.o && llvm-strip --strip-debug ebpf420x86.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=506 -D__TARGET_ARCH_x86 -c ebpf.c -o ebpf506x86.o && llvm-strip --strip-debug ebpf506x86.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=512 -D__TARGET_ARCH_x86 -c ebpf.c -o ebpf512x86.o && llvm-strip --strip-debug ebpf512x86.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=512 -D__TARGET_ARCH_x86 -D__CTX_EXTRA_PADDING -c ebpf.c -o ebpf512x86cep.o && llvm-strip --strip-debug ebpf512x86cep.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=416 -D__TARGET_ARCH_arm64 -c ebpf.c -o ebpf416arm64.o && llvm-strip --strip-debug ebpf416arm64.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=420 -D__TARGET_ARCH_arm64 -c ebpf.c -o ebpf420arm64.o && llvm-strip --strip-debug ebpf420arm64.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=506 -D__TARGET_ARCH_arm64 -c ebpf.c -o ebpf506arm64.o && llvm-strip --strip-debug ebpf506arm64.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=512 -D__TARGET_ARCH_arm64 -c ebpf.c -o ebpf512arm64.o && llvm-strip --strip-debug ebpf512arm64.o
RUN clang -g -O2 -target bpf -D__KERNEL_FROM=512 -D__TARGET_ARCH_arm64 -D__CTX_EXTRA_PADDING -c ebpf.c -o ebpf512arm64cep.o && llvm-strip --strip-debug ebpf512arm64cep.o

RUN echo -en '// generated - do not edit\npackage ebpftracer\n\nvar ebpfProgs = map[string][]struct {\n' > ebpf.go \
	&& echo -en '\tversion string\n' >> ebpf.go \
	&& echo -en '\tflags   string\n' >> ebpf.go \
	&& echo -en '\tprog    []byte\n' >> ebpf.go \
	&& echo -en '}{\n' >> ebpf.go \
	&& echo -en '\t"amd64": {\n' >> ebpf.go \
	&& echo -en '\t\t{"5.12", "ctx-extra-padding", []byte("' >> ebpf.go && gzip -c ebpf512x86cep.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"5.12", "", []byte("' >> ebpf.go && gzip -c ebpf512x86.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"5.6", "", []byte("' >> ebpf.go && gzip -c ebpf506x86.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"4.20", "", []byte("' >> ebpf.go && gzip -c ebpf420x86.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"4.16", "", []byte("' >> ebpf.go && gzip -c ebpf416x86.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t},\n'>> ebpf.go \
	&& echo -en '\t"arm64": {\n' >> ebpf.go \
	&& echo -en '\t\t{"5.12", "ctx-extra-padding", []byte("' >> ebpf.go && gzip -c ebpf512arm64cep.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"5.12", "", []byte("' >> ebpf.go && gzip -c ebpf512arm64.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"5.6", "", []byte("' >> ebpf.go && gzip -c ebpf506arm64.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"4.20", "", []byte("' >> ebpf.go && gzip -c ebpf420arm64.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t\t{"4.16", "", []byte("' >> ebpf.go && gzip -c ebpf416arm64.o | base64 -w0 >> ebpf.go && echo '")},' >> ebpf.go \
	&& echo -en '\t},\n'>> ebpf.go \
	&& echo -en '}\n'>> ebpf.go
