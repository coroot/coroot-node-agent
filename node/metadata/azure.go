package metadata

import (
	"encoding/json"
	"k8s.io/klog/v2"
	"net/http"
)

const (
	azureEndpoint = "http://169.254.169.254/metadata/instance"
)

type azureIp struct {
	Private string `json:"privateIpAddress"`
	Public  string `json:"publicIpAddress"`
}

type azureInterface struct {
	Ipv4 struct {
		IpAddress []azureIp `json:"ipAddress"`
	}
}

type azureInstanceMetadata struct {
	Compute struct {
		Region         string `json:"location"`
		Id             string `json:"vmID"`
		Type           string `json:"vmSize"`
		Zone           string `json:"zone"`
		SubscriptionId string `json:"subscriptionId"`
	}
	Network struct {
		Interface []azureInterface `json:"interface"`
	}
}

func getAzureMetadata() *CloudMetadata {
	req, err := http.NewRequest(http.MethodGet, azureEndpoint, nil)
	if err != nil {
		klog.Errorln(err)
		return nil
	}
	req.Header.Add("Metadata", "True")
	q := req.URL.Query()
	q.Add("format", "json")
	q.Add("api-version", "2021-05-01")
	req.URL.RawQuery = q.Encode()

	client := http.DefaultClient
	client.Timeout = metadataServiceTimeout

	resp, err := client.Do(req)
	if err != nil {
		klog.Errorln(err)
		return nil
	}
	if resp.StatusCode != 200 {
		klog.Errorln("metadata service response:", resp.Status)
		return nil
	}
	defer resp.Body.Close()

	instanceMd := &azureInstanceMetadata{}
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(instanceMd); err != nil {
		klog.Errorln("failed to unmarshall response of Azure metadata service:", err)
		return nil
	}
	md := &CloudMetadata{
		Provider:         CloudProviderAzure,
		AccountId:        instanceMd.Compute.SubscriptionId,
		InstanceId:       instanceMd.Compute.Id,
		InstanceType:     instanceMd.Compute.Type,
		Region:           instanceMd.Compute.Region,
		AvailabilityZone: instanceMd.Compute.Zone,
	}
	if len(instanceMd.Network.Interface) > 0 && len(instanceMd.Network.Interface[0].Ipv4.IpAddress) > 0 {
		md.LocalIPv4 = instanceMd.Network.Interface[0].Ipv4.IpAddress[0].Private
		md.PublicIPv4 = instanceMd.Network.Interface[0].Ipv4.IpAddress[0].Public
	}
	return md
}
