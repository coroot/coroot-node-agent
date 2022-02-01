package cgroup

import (
	"io/ioutil"
	"k8s.io/klog/v2"
	"strconv"
	"strings"
)

func readVariablesFromFile(filePath string) (map[string]uint64, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	res := map[string]uint64{}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 {
			v, err := strconv.ParseUint(parts[1], 10, 64)
			if err != nil {
				klog.Warningf(`failed to parse cgroup stat line "%s": %s`, line, err)
				continue
			}
			res[parts[0]] = v
		}
	}
	return res, nil
}

func readIntFromFile(filePath string) (int64, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
}

func readUintFromFile(filePath string) (uint64, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}
