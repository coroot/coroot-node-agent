//go:build windows

package metadata

func getAwsMetadata() *CloudMetadata {
	return &CloudMetadata{Provider: CloudProviderAWS}
}

func getGcpMetadata() *CloudMetadata {
	return &CloudMetadata{Provider: CloudProviderGCP}
}

func getIBMMetadata() *CloudMetadata {
	return &CloudMetadata{Provider: CloudProviderIBM}
}
