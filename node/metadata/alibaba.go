package metadata

import (
	"io"
	"net/http"

	"k8s.io/klog/v2"
)

const alibabaInstanceMetadataURL = "http://100.100.100.200/latest/meta-data/"

func getAlibabaMetadata() *CloudMetadata {
	var lastErr error
	getVar := func(path string) string {
		r, _ := http.NewRequest(http.MethodGet, alibabaInstanceMetadataURL+path, nil)
		resp, err := httpCallWithTimeout(r)
		if err != nil {
			lastErr = err
			return ""
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = err
			return ""
		}
		return string(data)
	}
	res := &CloudMetadata{
		Provider:         CloudProviderAlibaba,
		InstanceId:       getVar("instance-id"),
		Region:           getVar("region-id"),
		AvailabilityZone: getVar("zone-id"),
		AccountId:        getVar("owner-account-id"),
		InstanceType:     getVar("instance/instance-type"),
		LocalIPv4:        getVar("private-ipv4"),
	}
	if lastErr != nil {
		klog.Warningln(lastErr)
		return nil
	}
	return res
}
