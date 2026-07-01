package metadata

import (
	"strings"

	"k8s.io/klog/v2"
)

func GetInstanceMetadata(o Overrides) *CloudMetadata {
	if o.DisableCloudMetadata {
		klog.Infoln("cloud metadata service querying is disabled")
		return &CloudMetadata{}
	}
	provider := getCloudProvider()
	// An explicitly configured provider is an intentional, per-deployment
	// override (e.g. a DaemonSet pinned to a specific node pool). Honor it even
	// when auto-detection disagrees or is inconclusive. When left empty the
	// per-node auto-detection result is used, which is the right default for
	// hybrid clusters spanning several clouds and bare metal.
	if o.Provider != "" {
		provider = CloudProvider(o.Provider)
	}
	return GetMetadata(provider)
}

func cloudProviderByVendor(boardVendor, sysVendor string) CloudProvider {
	switch strings.TrimSpace(boardVendor) {
	case "Amazon EC2":
		return CloudProviderAWS
	case "Google":
		return CloudProviderGCP
	case "Microsoft Corporation":
		return CloudProviderAzure
	case "DigitalOcean":
		return CloudProviderDigitalOcean
	}
	switch strings.TrimSpace(sysVendor) {
	case "Hetzner":
		return CloudProviderHetzner
	case "Alibaba Cloud":
		return CloudProviderAlibaba
	case "Scaleway":
		return CloudProviderScaleway
	}
	return CloudProviderUnknown
}
