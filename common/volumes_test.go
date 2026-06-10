package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseKubernetesVolumeSource(t *testing.T) {
	// dynamically provisioned volumes (pv name is pvc-<uuid>)
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
		"pvc-4bf620ab-bb10-4cd6-803a-5be8735ccaf6",
		ParseKubernetesVolumeSource("/var/snap/microk8s/common/default-storage/coroot-coroot-data-pvc-4bf620ab-bb10-4cd6-803a-5be8735ccaf6"))

	// statically provisioned volumes (user-defined pv names)
	assert.Equal(t,
		"vls-restore",
		ParseKubernetesVolumeSource("/var/lib/kubelet/pods/2c1f8c7a-3a37-4e94-9d2b-0a4f9f8a1b6e/volumes/kubernetes.io~csi/vls-restore/mount"),
	)
	assert.Equal(t,
		"ledger-migration",
		ParseKubernetesVolumeSource("/var/lib/kubelet/pods/7f1d2b9e-8c44-4a0d-b1de-3f6f0c9f2a51/volumes/kubernetes.io~csi/ledger-migration/mount"),
	)
	assert.Equal(t,
		"data-on-nfs",
		ParseKubernetesVolumeSource("/var/lib/kubelet/pods/9a2b3c4d-5e6f-4a1b-8c9d-0e1f2a3b4c5d/volumes/kubernetes.io~nfs/data-on-nfs"),
	)
	assert.Equal(t,
		"legacy-ebs-volume",
		ParseKubernetesVolumeSource("/var/lib/kubelet/pods/1b2c3d4e-5f6a-4b1c-9d8e-7f0a1b2c3d4e/volumes/kubernetes.io~aws-ebs/legacy-ebs-volume"),
	)

	// non-persistent volume plugins must not produce a volume name
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
	assert.Equal(t,
		"",
		ParseKubernetesVolumeSource("/var/lib/kubelet/pods/db6e284a-fbab-4629-8f17-9f5fea38bea7/volumes/kubernetes.io~secret/tls-certs"),
	)
	assert.Equal(t,
		"",
		ParseKubernetesVolumeSource("/var/lib/kubelet/pods/db6e284a-fbab-4629-8f17-9f5fea38bea7/volumes/kubernetes.io~empty-dir/tmp"),
	)
	assert.Equal(t,
		"",
		ParseKubernetesVolumeSource("/var/lib/kubelet/pods/db6e284a-fbab-4629-8f17-9f5fea38bea7/volumes/kubernetes.io~downward-api/podinfo"),
	)
	assert.Equal(t,
		"",
		ParseKubernetesVolumeSource("/var/lib/docker/overlay2/0a1b2c3d4e5f/merged"),
	)
}
