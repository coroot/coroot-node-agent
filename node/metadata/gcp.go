package metadata

import (
	gcp "cloud.google.com/go/compute/metadata"
	"k8s.io/klog/v2"
	"net/http"
	"strings"
)

func getGcpMetadata() *CloudMetadata {
	hc := http.DefaultClient
	hc.Timeout = metadataServiceTimeout
	c := gcp.NewClient(hc)
	md := &CloudMetadata{
		Provider:   CloudProviderGCP,
		AccountId:  getGcpMetadataVariable(c, "project/project-id"),
		InstanceId: getGcpMetadataVariable(c, "instance/id"),
		LocalIPv4:  getGcpMetadataVariable(c, "instance/network-interfaces/0/ip"),
		PublicIPv4: getGcpMetadataVariable(c, "instance/network-interfaces/0/access-configs/0/external-ip"),
	}
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
