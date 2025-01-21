package metadata

import (
	"io"
	"net/http"
	"regexp"
	"strings"

	"k8s.io/klog/v2"
)

const scalewayInstanceMetadataURL = "http://169.254.42.42/conf"

var scalewayAZSuffix = regexp.MustCompile(`-(\d+)$`)

func getScalewayMetadata() *CloudMetadata {
	r, _ := http.NewRequest(http.MethodGet, scalewayInstanceMetadataURL, nil)
	resp, err := httpCallWithTimeout(r)
	if err != nil {
		klog.Warningln(err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		klog.Warningf("got %s from Scaleway metadata API", resp.Status)
		return nil
	}
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		klog.Warningln(err)
		return nil
	}
	md := map[string]string{}
	for _, l := range strings.Split(string(payload), "\n") {
		kv := strings.SplitN(l, "=", 2)
		if len(kv) != 2 {
			continue
		}
		md[kv[0]] = kv[1]
	}
	return &CloudMetadata{
		Provider:         CloudProviderScaleway,
		InstanceId:       md["ID"],
		Region:           scalewayAZSuffix.ReplaceAllString(md["ZONE"], ""),
		AvailabilityZone: md["ZONE"],
		InstanceType:     md["COMMERCIAL_TYPE"],
	}
}
