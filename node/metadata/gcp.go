package metadata

import (
	"strings"

	gcp "cloud.google.com/go/compute/metadata"
	"k8s.io/klog/v2"
)

func getGcpMetadata() *CloudMetadata {
	c := gcp.NewClient(nil)
	md := &CloudMetadata{Provider: CloudProviderGCP}
	if md.AccountId = getGcpMetadataVariable(c, "project/project-id"); md.AccountId == "" {
		return md
	}
	md.InstanceId = getGcpMetadataVariable(c, "instance/id")
	md.LocalIPv4 = getGcpMetadataVariable(c, "instance/network-interfaces/0/ip")
	md.PublicIPv4 = getGcpMetadataVariable(c, "instance/network-interfaces/0/access-configs/0/external-ip")

	switch strings.ToLower(getGcpMetadataVariable(c, "instance/scheduling/preemptible")) {
	case "false":
		md.LifeCycle = "on-demand"
	case "true":
		md.LifeCycle = "preemptible"
	}

	// projects/PROJECT_NUM/machineTypes/MACHINE_TYPE
	if parts := strings.SplitN(getGcpMetadataVariable(c, "instance/machine-type"), "/", 4); len(parts) == 4 {
		md.InstanceType = parts[3]
	}

	// projects/PROJECT_NUM/zones/ZONE
	if parts := strings.SplitN(getGcpMetadataVariable(c, "instance/zone"), "/", 4); len(parts) == 4 {
		md.AvailabilityZone = parts[3]
		if idx := strings.LastIndex(md.AvailabilityZone, "-"); idx != -1 {
			md.Region = md.AvailabilityZone[:idx]
		}
	}
	return md
}

func getGcpMetadataVariable(client *gcp.Client, path string) string {
	s, err := client.Get(path)
	if err != nil {
		klog.Errorln(path, err)
	}
	return s
}
