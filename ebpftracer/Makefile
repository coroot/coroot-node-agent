ebpf.go: $(wildcard ebpf/**.c)
	@echo ===BUILDING ebpf.go===
	docker rmi -f ebpftracer
	docker build -t ebpftracer --progress plain .
	docker run --rm --name ebpftracer ebpftracer cat /tmp/ebpf/ebpf.go > ./ebpf.go
	@echo

test: test_vm1 test_vm2 test_vm3 test_vm4 test_vm5

define test_in_vm
	@echo ===TESTING IN $(1)===
	vagrant ssh $(1) -c "uname -r && cd /tmp/src && sudo VM=$(1) go test -p 1 -count 1 -v ./ebpftracer/..."
	@echo
endef

test_vm1:
	$(call test_in_vm,ubuntu1810)

test_vm2:
	$(call test_in_vm,ubuntu2004)

test_vm3:
	$(call test_in_vm,ubuntu2010)

test_vm4:
	$(call test_in_vm,ubuntu2110)

test_vm5:
	$(call test_in_vm,ubuntu2204)

vms_start:
	vagrant up

vms_stop:
	vagrant suspend

vms_delete:
	vagrant destroy
