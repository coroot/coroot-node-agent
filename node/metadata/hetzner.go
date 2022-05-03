package metadata

import (
	"gopkg.in/yaml.v2"
	"k8s.io/klog/v2"
	"net/http"
)

const hetznerInstanceMetadataURL = "http://169.254.169.254/hetzner/v1/metadata"

type hetznerInstanceMetadata struct {
	AvailabilityZone string `yaml:"availability-zone"`
	InstanceId       string `yaml:"instance-id"`
	PublicIPv4       string `yaml:"public-ipv4"`
	LocalIPv4        string `yaml:"local-ipv4"`
	Region           string `yaml:"region"`
}

func getHetznerMetadata() *CloudMetadata {
	r, _ := http.NewRequest(http.MethodGet, hetznerInstanceMetadataURL, nil)
	resp, err := httpGetWithTimeout(r)
	if err != nil {
		klog.Errorln(err)
		return nil
	}
	defer resp.Body.Close()
	md := &hetznerInstanceMetadata{}
	decoder := yaml.NewDecoder(resp.Body)
	if err := decoder.Decode(md); err != nil {
		klog.Errorln("failed to unmarshall response of Hetzner metadata service:", err)
		return nil
	}
	res := &CloudMetadata{
		Provider:         CloudProviderHetzner,
		InstanceId:       md.InstanceId,
		Region:           md.Region,
		AvailabilityZone: md.AvailabilityZone,
		LocalIPv4:        md.LocalIPv4,
		PublicIPv4:       md.PublicIPv4,
	}
	return res
}
