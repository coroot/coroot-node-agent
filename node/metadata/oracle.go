package metadata

import (
	"encoding/json"
	"net/http"
	"regexp"

	"k8s.io/klog/v2"
)

var oracleAZSuffix = regexp.MustCompile(`-AD-(\d+)$`)

type oracleMetadata struct {
	Id                 string `json:"id"`
	Region             string `json:"canonicalRegionName"`
	AvailabilityDomain string `json:"availabilityDomain"`
	Shape              string `json:"shape"`
}

func getOracleMetadata() *CloudMetadata {
	r, _ := http.NewRequest(http.MethodGet, "http://169.254.169.254/opc/v2/instance/", nil)
	r.Header.Set("Authorization", "Bearer Oracle")
	resp, err := httpCallWithTimeout(r)
	if err != nil {
		klog.Warningln(err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		klog.Warningf("got %s from Oracle Cloud metadata API", resp.Status)
		return nil
	}
	md := oracleMetadata{}
	if err = json.NewDecoder(resp.Body).Decode(&md); err != nil {
		return nil
	}
	m := oracleAZSuffix.FindStringSubmatch(md.AvailabilityDomain)
	az := ""
	if len(m) == 2 {
		az = md.Region + "-ad-" + m[1]
	}
	return &CloudMetadata{
		Provider:         CloudProviderOracle,
		InstanceId:       md.Id,
		Region:           md.Region,
		AvailabilityZone: az,
		InstanceType:     md.Shape,
	}
}
