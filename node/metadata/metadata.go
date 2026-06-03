package metadata

import (
	"fmt"
	"net/http"
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
	CloudProviderOracle       CloudProvider = "Oracle"
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

type Overrides struct {
	Provider          string
	Region            string
	AvailabilityZone  string
	InstanceType      string
	InstanceLifeCycle string
}

func (md *CloudMetadata) ApplyOverrides(o Overrides) {
	if o.Provider != "" {
		md.Provider = CloudProvider(o.Provider)
	}
	if o.Region != "" {
		md.Region = o.Region
	}
	if o.AvailabilityZone != "" {
		md.AvailabilityZone = o.AvailabilityZone
	}
	if o.InstanceType != "" {
		md.InstanceType = o.InstanceType
	}
	if o.InstanceLifeCycle != "" {
		md.LifeCycle = o.InstanceLifeCycle
	}
}

func GetMetadata(provider CloudProvider) *CloudMetadata {
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
	case CloudProviderOracle:
		return getOracleMetadata()
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
