package common

import (
	"regexp"

	"github.com/coroot/coroot-node-agent/flags"
	"k8s.io/klog/v2"
)

type containerFilter struct {
	allowList []*regexp.Regexp
	denyList  []*regexp.Regexp
}

var ContainerFilter *containerFilter

func init() {
	var err error
	if ContainerFilter, err = newContainerFilter(*flags.ContainerAllowlist, *flags.ContainerDenylist); err != nil {
		klog.Exitf("invalid container filter: %s", err)
	}
}

func newContainerFilter(allowList, denyList []string) (*containerFilter, error) {
	f := &containerFilter{}
	klog.Infoln("container allowlist:", allowList)
	klog.Infoln("container denylist:", denyList)
	for _, v := range allowList {
		r, err := regexp.Compile(v)
		if err != nil {
			return nil, err
		}
		f.allowList = append(f.allowList, r)
	}
	for _, v := range denyList {
		r, err := regexp.Compile(v)
		if err != nil {
			return nil, err
		}
		f.denyList = append(f.denyList, r)
	}
	return f, nil
}

func (f *containerFilter) ShouldBeSkipped(containerId string) bool {
	if f.skippedByDenylist(containerId) {
		return true
	}
	return f.skippedByAllowlist(containerId)
}

func (f *containerFilter) skippedByAllowlist(containerId string) bool {
	if len(f.allowList) == 0 {
		return false
	}
	for _, v := range f.allowList {
		if v.MatchString(containerId) {
			return false
		}
	}
	return true
}

func (f *containerFilter) skippedByDenylist(containerId string) bool {
	if len(f.denyList) == 0 {
		return false
	}
	for _, v := range f.denyList {
		if v.MatchString(containerId) {
			return true
		}
	}
	return false
}
