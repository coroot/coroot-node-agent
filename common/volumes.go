package common

import (
	"regexp"
)

var (
	k8sVolumeDir = regexp.MustCompile(`.+(pvc-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}).*`)
)

func ParseKubernetesVolumeSource(source string) string {
	groups := k8sVolumeDir.FindStringSubmatch(source)
	if len(groups) != 2 {
		return ""
	}
	return groups[1]
}
