package node

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const defaultSysfsRoot = "/sys"

func readTrimmed(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(data)), true
}

func readFloat(path string) (float64, bool) {
	s, ok := readTrimmed(path)
	if !ok {
		return 0, false
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func listDir(path string) []string {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func linkBase(path string) string {
	target, err := os.Readlink(path)
	if err != nil {
		return ""
	}
	return filepath.Base(target)
}

func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// leadingNumber parses values like "4: ACTIVE" or "5: LinkUp".
func leadingNumber(s string) (float64, bool) {
	if i := strings.IndexByte(s, ':'); i > 0 {
		s = s[:i]
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return v, err == nil
}
