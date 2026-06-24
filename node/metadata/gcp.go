package metadata

import (
	"io"
	"net/http"
	"strings"

	"k8s.io/klog/v2"
)

func getGcpMetadata() *CloudMetadata {
	md := &CloudMetadata{Provider: CloudProviderGCP}

	c, cleanup := newMetadataClient()
	defer cleanup()

	if md.AccountId = getGcpMetadataVariable(c, "project/project-id"); md.AccountId == "" {
		return nil
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

func getGcpMetadataVariable(client *http.Client, path string) string {
	u := "http://169.254.169.254/computeMetadata/v1/" + strings.TrimLeft(path, "/")
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		klog.Errorln(path, err)
		return ""
	}
	req.Header.Set("Metadata-Flavor", "Google")
	res, err := client.Do(req)
	if err != nil {
		klog.Errorln(path, err)
		return ""
	}
	if res.StatusCode != 200 {
		klog.Errorln(path, res.Status)
		return ""
	}
	defer res.Body.Close()
	all, err := io.ReadAll(res.Body)
	if err != nil {
		klog.Errorln(path, err)
		return ""
	}
	return string(all)
}
