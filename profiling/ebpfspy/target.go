//go:build linux

package ebpfspy

type Target struct {
	ServiceName string
	ContainerID string
	Python      bool
}

type TargetFinder interface {
	FindTarget(pid uint32) *Target
	RemoveDeadPID(pid uint32)
	Reset(pid uint32)
	Update()
}
