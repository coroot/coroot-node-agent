package common

import "strings"

func IsNotExist(err error) bool {
	return strings.Contains(err.Error(), "no such file or directory") || strings.Contains(err.Error(), "no such process")
}
