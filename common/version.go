package common

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	versionRe = regexp.MustCompile(`^v?(\d+(\.\d+)*)`)
)

type Version struct {
	Major, Minor, Patch int
}

func NewVersion(major, minor, patch int) Version {
	return Version{Major: major, Minor: minor, Patch: patch}
}

func VersionFromString(version string) (Version, error) {
	var v Version
	matches := versionRe.FindStringSubmatch(version)
	if len(matches) == 0 {
		return v, fmt.Errorf("invalid version: %s", version)
	}
	parts := strings.Split(matches[1], ".")
	for i, p := range parts {
		ii, _ := strconv.Atoi(p)
		switch i {
		case 0:
			v.Major = ii
		case 1:
			v.Minor = ii
		case 2:
			v.Patch = ii
		default:
			break
		}
	}
	return v, nil
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

func (v Version) GreaterOrEqual(other Version) bool {
	switch {
	case v.Major > other.Major:
		return true
	case v.Major < other.Major:
		return false
	case v.Minor > other.Minor:
		return true
	case v.Minor < other.Minor:
		return false
	}
	return v.Patch >= other.Patch
}
