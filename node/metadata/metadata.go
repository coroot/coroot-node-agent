package metadata

import (
	"k8s.io/klog/v2"
	"os"
	"strings"
	"time"
)

const metadataServiceTimeout = 5 * time.Second

type CloudProvider string

const (
	CloudProviderAWS     CloudProvider = "AWS"
	CloudProviderGCP     CloudProvider = "GCP"
	CloudProviderAzure   CloudProvider = "Azure"
	CloudProviderUnknown CloudProvider = ""
)

type CloudMetadata struct {
	Provider           CloudProvider
	AccountId          string
	InstanceId         string
	InstanceType       string
	LifeCycle          string
	Region             string
	AvailabilityZone   string
	AvailabilityZoneId string
	LocalIPv4          string
	PublicIPv4         string
}

func getCloudProvider() CloudProvider {
	if d, err := os.ReadFile("/sys/hypervisor/uuid"); err == nil { // AWS Xen instances
		if strings.HasPrefix(strings.ToLower(string(d)), "ec2") {
			return CloudProviderAWS
		}
	}
	if vendor, err := os.ReadFile("/sys/class/dmi/id/board_vendor"); err == nil {
		switch strings.TrimSpace(string(vendor)) {
		case "Amazon EC2":
			return CloudProviderAWS
		case "Google":
			return CloudProviderGCP
		case "Microsoft Corporation":
			return CloudProviderAzure
		}
	}
	return CloudProviderUnknown
}

func GetInstanceMetadata() *CloudMetadata {
	provider := getCloudProvider()
	klog.Infoln("cloud provider:", provider)
	switch provider {
	case CloudProviderAWS:
		return getAwsMetadata()
	case CloudProviderGCP:
		return getGcpMetadata()
	case CloudProviderAzure:
		return getAzureMetadata()
	}
	return nil
}
