package common

import (
	"regexp"
)

var (
	k8sVolumeDir = regexp.MustCompile(`.+/(volumes/kubernetes.io~([^/]+)|volume-subpaths|k3s/storage)/(pvc-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})`)
)

func ParseKubernetesVolumeSource(source string) string {
	groups := k8sVolumeDir.FindStringSubmatch(source)
	if len(groups) != 4 {
		return ""
	}
	provisioner, volume := groups[2], groups[3]
	switch provisioner {
	case "secret", "configmap", "empty-dir", "projected":
		return ""
	}
	return volume
}
