package node

import (
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
)

func uptime(procRoot string) (float64, error) {
	data, err := os.ReadFile(path.Join(procRoot, "uptime"))
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) != 2 {
		return 0, fmt.Errorf("invalid format of /proc/uptime")
	}
	return strconv.ParseFloat(fields[0], 64)
}
