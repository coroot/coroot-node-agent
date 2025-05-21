package metadata

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"k8s.io/klog/v2"
)

const metadataServiceTimeout = 5 * time.Second

type CloudProvider string

const (
	CloudProviderAWS          CloudProvider = "AWS"
	CloudProviderGCP          CloudProvider = "GCP"
	CloudProviderAzure        CloudProvider = "Azure"
	CloudProviderHetzner      CloudProvider = "Hetzner"
	CloudProviderDigitalOcean CloudProvider = "DigitalOcean"
	CloudProviderAlibaba      CloudProvider = "Alibaba"
	CloudProviderScaleway     CloudProvider = "Scaleway"
	CloudProviderIBM          CloudProvider = "IBM"
	CloudProviderUnknown      CloudProvider = ""
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
		case "DigitalOcean":
			return CloudProviderDigitalOcean
		}
	}
	if vendor, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
		switch strings.TrimSpace(string(vendor)) {
		case "Hetzner":
			return CloudProviderHetzner
		case "Alibaba Cloud":
			return CloudProviderAlibaba
		case "Scaleway":
			return CloudProviderScaleway
		}
	}
	if vendor, err := os.ReadFile("/sys/class/dmi/id/chassis_vendor"); err == nil {
		if strings.HasPrefix(string(vendor), "IBM:Cloud Compute Server") {
			return CloudProviderIBM
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
	case CloudProviderHetzner:
		return getHetznerMetadata()
	case CloudProviderDigitalOcean:
		return getDigitalOceanMetadata()
	case CloudProviderAlibaba:
		return getAlibabaMetadata()
	case CloudProviderScaleway:
		return getScalewayMetadata()
	case CloudProviderIBM:
		return getIBMMetadata()
	}
	return nil
}

func httpCallWithTimeout(r *http.Request) (*http.Response, error) {
	client := http.DefaultClient
	client.Timeout = metadataServiceTimeout
	resp, err := client.Do(r)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("metadata service response: %s", resp.Status)
	}
	return resp, nil
}
