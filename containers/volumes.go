package containers

import "regexp"

var (
	k8sVolumeDir = regexp.MustCompile(`.+/volumes/kubernetes.io~([^/]+)/([^/]+)`)
)

func parseVolumeSource(source string) (string, string) {
	groups := k8sVolumeDir.FindStringSubmatch(source)
	if len(groups) != 3 {
		return "", ""
	}
	provisioner, volume := groups[1], groups[2]
	switch provisioner {
	case "secret", "configmap", "empty-dir":
		return "", ""
	}
	return provisioner, volume
}
