//go:build windows

package metadata

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWindowsAwsMetadata(t *testing.T) {
	values := map[string]string{
		"instance-id":                    "i-123",
		"instance-life-cycle":            "spot",
		"instance-type":                  "m7i.large",
		"placement/region":               "us-east-1",
		"placement/availability-zone":    "us-east-1a",
		"placement/availability-zone-id": "use1-az1",
		"local-ipv4":                     "10.0.0.10",
		"public-ipv4":                    "203.0.113.10",
		"identity-credentials/ec2/info":  `{"AccountId":"123456789012"}`,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/latest/api/token":
			fmt.Fprint(w, "aws-token")
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/latest/meta-data/"):
			if got := r.Header.Get("X-aws-ec2-metadata-token"); got != "aws-token" {
				t.Errorf("token header=%q, want aws-token", got)
			}
			path := strings.TrimPrefix(r.URL.Path, "/latest/meta-data/")
			if value, ok := values[path]; ok {
				fmt.Fprint(w, value)
				return
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	old := awsInstanceMetadataURL
	awsInstanceMetadataURL = server.URL + "/latest"
	defer func() { awsInstanceMetadataURL = old }()

	md := getAwsMetadata()
	if md.Provider != CloudProviderAWS || md.AccountId != "123456789012" || md.InstanceId != "i-123" || md.InstanceType != "m7i.large" || md.LifeCycle != "spot" || md.Region != "us-east-1" || md.AvailabilityZone != "us-east-1a" || md.AvailabilityZoneId != "use1-az1" || md.LocalIPv4 != "10.0.0.10" || md.PublicIPv4 != "203.0.113.10" {
		t.Fatalf("unexpected AWS metadata: %+v", md)
	}
}

func TestWindowsGcpMetadata(t *testing.T) {
	values := map[string]string{
		"project/project-id":               "project-1",
		"instance/id":                      "987654321",
		"instance/network-interfaces/0/ip": "10.1.0.10",
		"instance/network-interfaces/0/access-configs/0/external-ip": "203.0.113.20",
		"instance/scheduling/preemptible":                            "true",
		"instance/machine-type":                                      "projects/123/machineTypes/n2-standard-4",
		"instance/zone":                                              "projects/123/zones/us-central1-b",
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Metadata-Flavor"); got != "Google" {
			t.Errorf("Metadata-Flavor=%q, want Google", got)
		}
		path := strings.TrimPrefix(r.URL.Path, "/computeMetadata/v1/")
		if value, ok := values[path]; ok {
			fmt.Fprint(w, value)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	old := gcpMetadataURL
	gcpMetadataURL = server.URL + "/computeMetadata/v1"
	defer func() { gcpMetadataURL = old }()

	md := getGcpMetadata()
	if md.Provider != CloudProviderGCP || md.AccountId != "project-1" || md.InstanceId != "987654321" || md.InstanceType != "n2-standard-4" || md.LifeCycle != "preemptible" || md.Region != "us-central1" || md.AvailabilityZone != "us-central1-b" || md.LocalIPv4 != "10.1.0.10" || md.PublicIPv4 != "203.0.113.20" {
		t.Fatalf("unexpected GCP metadata: %+v", md)
	}
}

func TestWindowsIBMMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/instance_identity/v1/token":
			if r.Method != http.MethodPut {
				t.Errorf("token method=%s, want PUT", r.Method)
			}
			if got := r.Header.Get("Metadata-Flavor"); got != "ibm" {
				t.Errorf("Metadata-Flavor=%q, want ibm", got)
			}
			fmt.Fprint(w, `{"access_token":"ibm-token"}`)
		case "/metadata/v1/instance":
			if got := r.Header.Get("Authorization"); got != "Bearer ibm-token" {
				t.Errorf("Authorization=%q, want Bearer ibm-token", got)
			}
			fmt.Fprint(w, `{"id":"ibm-instance","crn":"crn:v1:bluemix:public:is:us-south-1:a/account-123::instance:ibm-instance","profile":{"name":"bx2-4x16"},"zone":{"name":"us-south-1"},"lifecycle":"spot"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	old := ibmInstanceMetadataAddress
	ibmInstanceMetadataAddress = strings.TrimPrefix(server.URL, "http://")
	defer func() { ibmInstanceMetadataAddress = old }()

	md := getIBMMetadata()
	if md.Provider != CloudProviderIBM || md.AccountId != "account-123" || md.InstanceId != "ibm-instance" || md.InstanceType != "bx2-4x16" || md.LifeCycle != "spot" || md.Region != "us-south" || md.AvailabilityZone != "us-south-1" {
		t.Fatalf("unexpected IBM metadata: %+v", md)
	}
}

func TestIBMAccountIDFromCRN(t *testing.T) {
	if got := ibmAccountIDFromCRN("crn:v1:bluemix:public:is:us-south-1:a/account-123::instance:id"); got != "account-123" {
		t.Fatalf("account=%q, want account-123", got)
	}
}
