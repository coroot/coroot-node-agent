package metadata

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"k8s.io/klog/v2"
)

const awsInstanceMetadataURL = "http://169.254.169.254/latest"

func getAwsToken() (string, error) {
	client, cleanup := newMetadataClient()
	defer cleanup()

	r, _ := http.NewRequest(http.MethodPut, awsInstanceMetadataURL+"/api/token", nil)
	r.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	resp, err := client.Do(r)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", errors.New(resp.Status)
	}
	defer resp.Body.Close()
	token, err := io.ReadAll(resp.Body)
	return string(token), err
}

func getAwsMetadata() *CloudMetadata {
	md := &CloudMetadata{Provider: CloudProviderAWS}
	token, err := getAwsToken()
	if err != nil {
		klog.Errorln("failed to get token:", err)
		return md
	}

	md = &CloudMetadata{
		Provider:           CloudProviderAWS,
		InstanceId:         getAwsMetadataVariable(token, "instance-id"),
		LifeCycle:          getAwsMetadataVariable(token, "instance-life-cycle"),
		InstanceType:       getAwsMetadataVariable(token, "instance-type"),
		Region:             getAwsMetadataVariable(token, "placement/region"),
		AvailabilityZone:   getAwsMetadataVariable(token, "placement/availability-zone"),
		AvailabilityZoneId: getAwsMetadataVariable(token, "placement/availability-zone-id"),
		LocalIPv4:          getAwsMetadataVariable(token, "local-ipv4"),
		PublicIPv4:         getAwsMetadataVariable(token, "public-ipv4"),
	}
	if infoJson := getAwsMetadataVariable(token, "identity-credentials/ec2/info"); infoJson != "" {
		m := map[string]string{}
		if err := json.Unmarshal([]byte(infoJson), &m); err != nil {
			klog.Errorln(err)
		} else {
			md.AccountId = m["AccountId"]
		}
	}
	return md
}

func getAwsMetadataVariable(token string, path string) string {
	r, _ := http.NewRequest(http.MethodGet, awsInstanceMetadataURL+"/meta-data/"+path, nil)
	r.Header.Set("X-aws-ec2-metadata-token", string(token))
	resp, err := httpCallWithTimeout(r)
	if err != nil {
		klog.Errorln(err)
		return ""
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		klog.Errorln(path, err)
		return ""
	}
	return string(payload)
}
