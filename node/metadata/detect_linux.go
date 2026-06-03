//go:build linux

package metadata

import (
	"os"
	"strings"
)

func getCloudProvider() CloudProvider {
	if d, err := os.ReadFile("/sys/hypervisor/uuid"); err == nil { // AWS Xen instances
		if strings.HasPrefix(strings.ToLower(string(d)), "ec2") {
			return CloudProviderAWS
		}
	}
	boardVendor, _ := os.ReadFile("/sys/class/dmi/id/board_vendor")
	sysVendor, _ := os.ReadFile("/sys/class/dmi/id/sys_vendor")
	if p := cloudProviderByVendor(string(boardVendor), string(sysVendor)); p != CloudProviderUnknown {
		return p
	}
	if vendor, err := os.ReadFile("/sys/class/dmi/id/chassis_vendor"); err == nil {
		if strings.HasPrefix(string(vendor), "IBM:Cloud Compute Server") {
			return CloudProviderIBM
		}
	}
	if vendor, err := os.ReadFile("/sys/class/dmi/id/chassis_asset_tag"); err == nil {
		if strings.TrimSpace(string(vendor)) == "OracleCloud.com" {
			return CloudProviderOracle
		}
	}

	return CloudProviderUnknown
}
