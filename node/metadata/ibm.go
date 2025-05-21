package metadata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"

	"github.com/coroot/coroot-node-agent/proc"
	"k8s.io/klog/v2"
)

const ibmInstanceMetadataAddress = "api.metadata.cloud.ibm.com"

var ibmAZSuffix = regexp.MustCompile(`-(\d+)$`)

type ibmTokenResponse struct {
	AccessToken string `json:"access_token"`
}

type ibmMetadata struct {
	Id      string `json:"id"`
	Profile struct {
		Name string `json:"name"`
	} `json:"profile"`
	Zone struct {
		Name string `json:"name"`
	} `json:"zone"`
}

func getIBMToken(scheme string) (string, error) {
	// a token must be retrieved using the host net NS because the metadata service sets IP TTL to 1 on all response packets
	hostNetNs, err := proc.GetHostNetNs()
	if err != nil {
		return "", err
	}
	defer hostNetNs.Close()
	agentNetNs, err := proc.GetSelfNetNs()
	if err != nil {
		return "", err
	}
	defer agentNetNs.Close()

	url := fmt.Sprintf("%s://%s/instance_identity/v1/token?version=2025-04-22", scheme, ibmInstanceMetadataAddress)

	r, _ := http.NewRequest(http.MethodPut, url, nil)
	r.Header.Set("Metadata-Flavor", "ibm")

	client := http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, addr string) (conn net.Conn, err error) {
				err = proc.ExecuteInNetNs(hostNetNs, agentNetNs, func() error {
					conn, err = net.DialTimeout(network, addr, metadataServiceTimeout)
					return err
				})
				return conn, err
			},
		},
	}
	resp, err := client.Do(r)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", errors.New(resp.Status)
	}
	defer resp.Body.Close()
	tr := ibmTokenResponse{}
	err = json.NewDecoder(resp.Body).Decode(&tr)
	return tr.AccessToken, err
}

func getIBMMetadata() *CloudMetadata {
	scheme := "http"

	token, err := getIBMToken(scheme)
	if err != nil {
		scheme = "https"
		if token, err = getIBMToken(scheme); err != nil {
			klog.Warningln(err)
			return nil
		}
	}
	url := fmt.Sprintf("%s://%s/metadata/v1/instance?version=2025-04-22", scheme, ibmInstanceMetadataAddress)
	r, _ := http.NewRequest(http.MethodGet, url, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	resp, err := httpCallWithTimeout(r)
	if err != nil {
		klog.Warningln(err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		klog.Warningf("got %s from IBM metadata API", resp.Status)
		return nil
	}
	md := ibmMetadata{}
	if err = json.NewDecoder(resp.Body).Decode(&md); err != nil {
		return nil
	}

	return &CloudMetadata{
		Provider:         CloudProviderIBM,
		InstanceId:       md.Id,
		Region:           ibmAZSuffix.ReplaceAllString(md.Zone.Name, ""),
		AvailabilityZone: md.Zone.Name,
		InstanceType:     md.Profile.Name,
	}
}
