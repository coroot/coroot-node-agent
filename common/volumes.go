package common

import (
	"regexp"
)

var (
	k8sVolumeDir = regexp.MustCompile(`.+(pvc-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}).*`)

	// kubelet mounts persistent volumes at /var/lib/kubelet/pods/<pod-uid>/volumes/kubernetes.io~<plugin>/<pv-name>/...,
	// where <pv-name> is `pvc-<uuid>` only for dynamically provisioned volumes;
	// statically provisioned volumes keep their user-defined names
	k8sPersistentVolumeDir = regexp.MustCompile(`/volumes/kubernetes\.io~(?:csi|aws-ebs|gce-pd|azure-disk|azure-file|nfs|iscsi|rbd|cephfs|fc|portworx-volume|vsphere-volume|local-volume)/([^/]+)`)
)

func ParseKubernetesVolumeSource(source string) string {
	if groups := k8sVolumeDir.FindStringSubmatch(source); len(groups) == 2 {
		return groups[1]
	}
	if groups := k8sPersistentVolumeDir.FindStringSubmatch(source); len(groups) == 2 {
		return groups[1]
	}
	return ""
}
