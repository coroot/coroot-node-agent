package node

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetNodeDisks(t *testing.T) {
	procRoot = "fixtures"
	d, err := GetDisks()
	assert.Nil(t, err)
	assert.Equal(t,
		DevStat{
			Name:             "vda",
			MajorMinor:       "254:0",
			ReadOps:          10.,
			WriteOps:         50.,
			BytesRead:        30. * 512,
			BytesWritten:     70. * 512,
			ReadTimeSeconds:  40. / 1000,
			WriteTimeSeconds: 80. / 1000,
			IoTimeSeconds:    100. / 1000,
		},
		*d.GetParentBlockDevice("254:0"),
	)
	assert.Equal(t,
		DevStat{
			Name:             "nvme0n1",
			MajorMinor:       "259:0",
			ReadOps:          11146,
			WriteOps:         2.3639172e+07,
			BytesRead:        3.60193536e+08,
			BytesWritten:     3.80286784512e+11,
			ReadTimeSeconds:  1.614,
			WriteTimeSeconds: 5380.297,
			IoTimeSeconds:    26059.968},
		*d.GetParentBlockDevice("259:4"),
	)
	names := func(devices []DevStat) []string {
		var res []string
		for _, d := range devices {
			res = append(res, d.Name)
		}
		sort.Strings(res)
		return res
	}

	assert.Equal(t,
		[]string{"dm-0", "md1", "mmcblk1", "mmcblk2", "nvme0n1", "nvme1n1", "rbd0", "rbd1", "sda", "sdb", "vda", "xvda"},
		names(d.BlockDevices()),
	)
}
