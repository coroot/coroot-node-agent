# Contributing

Thank you for your interest in contributing to Coroot!
Below are some basic guidelines.


## Requirements
* Linux ≥v4.16 (amd64, arm64)
* Go v1.23


## Running
```shell
sudo go run main.go
```

```shell
curl http://127.0.0.1:80/metrics
```

## Pull Request Checklist

* Branch from the main branch and, if needed, rebase to the current main branch before submitting your pull request. If it doesn't merge cleanly with main you may be asked to rebase your changes.
* Commits should be as small as possible, while ensuring that each commit is correct independently (i.e., each commit should compile and pass tests).
* Add tests relevant to the fixed bug or new feature.
* Use `make lint` to run linters and ensure formatting is correct.
* Run the unit tests suite `make test`.


## eBPF

If you are changing eBPF code, you need to generate the `ebpftracer/ebpf.go` file:
```shell
cd ebpftracer
make build
```
