//go:build windows

package cgroup

type Cgroup struct{}

func Init() error {
	return nil
}
