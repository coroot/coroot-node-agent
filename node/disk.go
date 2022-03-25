package node

import (
	"io/ioutil"
	"k8s.io/klog/v2"
	"path"
	"regexp"
	"strconv"
	"strings"
)

var blockDevice = regexp.MustCompile(`^(dm-\d+|(s|h|xv|v)d[a-z]|md\d+|nvme\d+n\d+|rbd\d+)`)

type DevStat struct {
	Name             string
	MajorMinor       string
	ReadOps          float64
	WriteOps         float64
	BytesRead        float64
	BytesWritten     float64
	ReadTimeSeconds  float64
	WriteTimeSeconds float64
	IoTimeSeconds    float64
}

type Disks struct {
	byMajorMinor map[string]DevStat
}

func (disks *Disks) BlockDevices() []DevStat {
	var res []DevStat
	for _, d := range disks.byMajorMinor {
		groups := blockDevice.FindStringSubmatch(d.Name)
		if len(groups) < 2 {
			continue
		}
		if groups[1] == d.Name {
			res = append(res, d)
		}
	}
	return res
}

func (disks *Disks) GetParentBlockDevice(majorMinor string) *DevStat {
	dev, ok := disks.byMajorMinor[majorMinor]
	if !ok {
		return nil
	}
	groups := blockDevice.FindStringSubmatch(dev.Name)
	if len(groups) < 2 {
		return nil
	}
	parentName := groups[1]
	for _, d := range disks.byMajorMinor {
		if d.Name == parentName {
			return &d
		}
	}
	return nil
}

func GetDisks() (*Disks, error) {
	data, err := ioutil.ReadFile(path.Join(procRoot, "diskstats"))
	if err != nil {
		return nil, err
	}
	disks := &Disks{
		byMajorMinor: map[string]DevStat{},
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 14 {
			continue
		}
		deviceName := fields[2]
		values, err := parseFloats(fields[3:])
		if err != nil {
			klog.Warningf(`invalid diskstats line "%s": %s`, line, err)
			continue
		}
		majorMinor := fields[0] + ":" + fields[1]
		disks.byMajorMinor[majorMinor] = DevStat{
			Name:             deviceName,
			MajorMinor:       majorMinor,
			ReadOps:          values[0],
			BytesRead:        values[2] * 512,
			ReadTimeSeconds:  values[3] / 1000,
			WriteOps:         values[4],
			BytesWritten:     values[6] * 512,
			WriteTimeSeconds: values[7] / 1000,
			IoTimeSeconds:    values[9] / 1000,
		}
	}
	return disks, nil
}

func parseFloats(input []string) ([]float64, error) {
	res := make([]float64, len(input))
	for i, strValue := range input {
		v, err := strconv.ParseFloat(strValue, 64)
		if err != nil {
			return nil, err
		}
		res[i] = v
	}
	return res, nil
}
