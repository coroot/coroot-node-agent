package common

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestParseKubernetesVolumeSource(t *testing.T) {
	assert.Equal(t,
		"pvc-90af9c02-ec70-446a-a16a-3ce17d4f42b4",
		ParseKubernetesVolumeSource("/var/lib/kubelet/pods/ed56844b-2ad5-4858-9305-abea47bd39fc/volumes/kubernetes.io~csi/pvc-90af9c02-ec70-446a-a16a-3ce17d4f42b4/mount"),
	)
	assert.Equal(t,
		"pvc-0307b722-e448-4d73-9d75-091ebf367264",
		ParseKubernetesVolumeSource("/var/lib/kubelet/pods/adf669ca-c3f8-49de-9ad4-9dd66721dc0d/volume-subpaths/pvc-0307b722-e448-4d73-9d75-091ebf367264/pg/0"),
	)
	assert.Equal(t,
		"pvc-d0c0cc92-ef36-4b4f-90c0-5c5ed489df0b",
		ParseKubernetesVolumeSource("/var/lib/rancher/k3s/storage/pvc-d0c0cc92-ef36-4b4f-90c0-5c5ed489df0b_default_mongod-data-mongo-psmdb-db-rs0-0"))

	assert.Equal(t,
		"",
		ParseKubernetesVolumeSource("/var/lib/kubelet/pods/adf669ca-c3f8-49de-9ad4-9dd66721dc0d/volumes/kubernetes.io~projected/kube-api-access-jvvq6"),
	)
	assert.Equal(t,
		"",
		ParseKubernetesVolumeSource("/var/lib/kubelet/pods/7cac0d4b-0562-4a25-bbd9-601c60048eb9/etc-hosts"))

	assert.Equal(t,
		"",
		ParseKubernetesVolumeSource("/var/lib/kubelet/pods/db6e284a-fbab-4629-8f17-9f5fea38bea7/volumes/kubernetes.io~configmap/config-volume"),
	)
}
