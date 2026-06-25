//go:build windows

package metadata

import (
	"strings"

	"github.com/siderolabs/go-smbios/smbios"
)

func getCloudProvider() CloudProvider {
	s, err := smbios.New()
	if err != nil {
		return CloudProviderUnknown
	}
	if strings.HasPrefix(strings.ToLower(s.SystemInformation.UUID), "ec2") {
		return CloudProviderAWS
	}
	if p := cloudProviderByVendor(s.BaseboardInformation.Manufacturer, s.SystemInformation.Manufacturer); p != CloudProviderUnknown {
		return p
	}
	if strings.HasPrefix(s.SystemInformation.Manufacturer, "IBM:Cloud Compute Server") {
		return CloudProviderIBM
	}
	if s.SystemInformation.Manufacturer == "OracleCloud.com" {
		return CloudProviderOracle
	}
	return CloudProviderUnknown
}
