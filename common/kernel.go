package common

import "regexp"

var (
	kernelVersionRe = regexp.MustCompile(`^(\d+\.\d+)`)
)

func KernelMajorMinor(version string) string {
	return kernelVersionRe.FindString(version)
}
