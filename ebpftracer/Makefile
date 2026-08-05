build:
	@echo ===BUILDING===
	docker rmi -f ebpftracer
	docker build -t ebpftracer --progress plain .
	docker run --rm --name ebpftracer ebpftracer cat /tmp/ebpf/ebpf.go > ./ebpf.go
	@echo

# the tracer tests load eBPF programs, so they need root on a Linux host and
# are skipped unless VM is set
test:
	sudo VM=1 go test -p 1 -count 1 -v ./...
