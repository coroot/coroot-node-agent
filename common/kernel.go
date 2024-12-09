package common

import (
	"fmt"
)

var (
	kernelVersion Version
)

func SetKernelVersion(version string) error {
	v, err := VersionFromString(version)
	if err != nil || v.Major == 0 {
		return fmt.Errorf("invalid kernel version: %s", version)
	}
	kernelVersion = v
	return nil
}

func GetKernelVersion() Version {
	return kernelVersion
}
