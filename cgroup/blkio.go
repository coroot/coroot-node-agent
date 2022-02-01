package cgroup

import (
	"io/ioutil"
	"k8s.io/klog/v2"
	"path"
	"strconv"
	"strings"
)

type BlkioStat struct {
	ReadOps      uint64
	WriteOps     uint64
	ReadBytes    uint64
	WrittenBytes uint64
}

func (cg *Cgroup) BlkioStat() (map[string]BlkioStat, error) {
	ops, err := readBlkioStatFile(path.Join(cgRoot, "blkio", cg.subsystems["blkio"], "blkio.throttle.io_serviced"))
	if err != nil {
		return nil, err
	}
	bytes, err := readBlkioStatFile(path.Join(cgRoot, "blkio", cg.subsystems["blkio"], "blkio.throttle.io_service_bytes"))
	if err != nil {
		return nil, err
	}
	res := map[string]BlkioStat{}
	for _, v := range ops {
		stat := res[v.majorMinor]
		switch v.name {
		case "Read":
			stat.ReadOps = v.value
		case "Write":
			stat.WriteOps = v.value
		}
		res[v.majorMinor] = stat
	}
	for _, v := range bytes {
		stat := res[v.majorMinor]
		switch v.name {
		case "Read":
			stat.ReadBytes = v.value
		case "Write":
			stat.WrittenBytes = v.value
		}
		res[v.majorMinor] = stat
	}
	return res, nil
}

type blkioVariable struct {
	majorMinor string
	name       string
	value      uint64
}

func readBlkioStatFile(filePath string) ([]blkioVariable, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var res []blkioVariable
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) != 3 {
			continue
		}
		v, err := strconv.ParseUint(parts[2], 10, 64)
		if err != nil {
			klog.Warningf(`failed to parse blkio stat line "%s": %s`, line, err)
			continue
		}
		res = append(res, blkioVariable{
			majorMinor: parts[0],
			name:       parts[1],
			value:      v,
		})
	}
	return res, nil
}
