package metadata

import "strings"

func GetInstanceMetadata() *CloudMetadata {
	return GetMetadata(getCloudProvider())
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
