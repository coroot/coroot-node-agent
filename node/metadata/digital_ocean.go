package metadata

import (
	"io"
	"net/http"

	"k8s.io/klog/v2"
)

const doInstanceMetadataURL = "http://169.254.169.254/metadata/v1/"

func getDigitalOceanMetadata() *CloudMetadata {
	var lastErr error
	getVar := func(path string) string {
		r, _ := http.NewRequest(http.MethodGet, doInstanceMetadataURL+path, nil)
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
		Provider:   CloudProviderDigitalOcean,
		InstanceId: getVar("id"),
		Region:     getVar("region"),
	}
	res.AvailabilityZone = res.Region
	if lastErr != nil {
		klog.Warningln(lastErr)
		return nil
	}
	return res
}
