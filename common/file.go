package common

import (
	"os"
	"strconv"
	"strings"
)

func ReadIntFromFile(filePath string) (int64, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
}

func ReadUintFromFile(filePath string) (uint64, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
}
