package metadata

import (
	"fmt"
	"k8s.io/klog/v2"
	"net/http"
	"os"
	"strings"
	"time"
)

const metadataServiceTimeout = 5 * time.Second

type CloudProvider string

const (
	CloudProviderAWS          CloudProvider = "AWS"
	CloudProviderGCP          CloudProvider = "GCP"
	CloudProviderAzure        CloudProvider = "Azure"
	CloudProviderHetzner      CloudProvider = "Hetzner"
	CloudProviderDigitalOcean CloudProvider = "DigitalOcean"
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
		if strings.TrimSpace(string(vendor)) == "Hetzner" {
			return CloudProviderHetzner
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
	}
	return nil
}

func httpGetWithTimeout(r *http.Request) (*http.Response, error) {
	client := http.DefaultClient
	client.Timeout = metadataServiceTimeout
	resp, err := client.Do(r)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		klog.Errorln()
		return nil, fmt.Errorf("metadata service response: %s", resp.Status)
	}
	return resp, nil
}
