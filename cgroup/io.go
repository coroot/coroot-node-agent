package cgroup

import (
	"io/ioutil"
	"path"
	"strconv"
	"strings"

	"k8s.io/klog/v2"
)

type IOStat struct {
	ReadOps      uint64
	WriteOps     uint64
	ReadBytes    uint64
	WrittenBytes uint64
}

func (cg *Cgroup) IOStat() map[string]IOStat {
	if cg.Version == V1 {
		st, _ := cg.ioStatV1()
		return st
	}
	st, _ := cg.ioStatV2()
	return st
}

func (cg *Cgroup) ioStatV1() (map[string]IOStat, error) {
	if cg.subsystems["blkio"] == "/" {
		return nil, nil
	}
	ops, err := readBlkioStatFile(path.Join(cgRoot, "blkio", cg.subsystems["blkio"], "blkio.throttle.io_serviced"))
	if err != nil {
		return nil, err
	}
	bytes, err := readBlkioStatFile(path.Join(cgRoot, "blkio", cg.subsystems["blkio"], "blkio.throttle.io_service_bytes"))
	if err != nil {
		return nil, err
	}
	res := map[string]IOStat{}
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

func (cg *Cgroup) ioStatV2() (map[string]IOStat, error) {
	payload, err := ioutil.ReadFile(path.Join(cgRoot, cg.subsystems[""], "io.stat"))
	if err != nil {
		return nil, err
	}
	res := map[string]IOStat{}
	for _, line := range strings.Split(string(payload), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}
		s := IOStat{}
		for _, value := range parts[1:] {
			if kv := strings.SplitN(value, "=", 2); len(kv) == 2 {
				v, err := strconv.ParseUint(kv[1], 10, 64)
				if err != nil {
					continue
				}
				switch kv[0] {
				case "rbytes":
					s.ReadBytes = v
				case "wbytes":
					s.WrittenBytes = v
				case "rios":
					s.ReadOps = v
				case "wios":
					s.WriteOps = v
				}
			}
		}
		res[parts[0]] = s
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
