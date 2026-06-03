//go:build windows

package containers

import (
	"regexp"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"k8s.io/klog/v2"
)

var perUserSuffix = regexp.MustCompile(`_[0-9a-f]+$`)

func discoverServices() []*Container {
	m, err := mgr.Connect()
	if err != nil {
		klog.Errorln("failed to connect to SCM:", err)
		return nil
	}
	defer m.Disconnect()

	names, err := m.ListServices()
	if err != nil {
		klog.Errorln("failed to list containers:", err)
		return nil
	}

	trees := processTrees()

	var out []*Container
	for _, name := range names {
		if perUserSuffix.MatchString(name) {
			continue
		}

		s, err := m.OpenService(name)
		if err != nil {
			continue
		}

		status, err := s.Query()
		if err != nil {
			s.Close()
			continue
		}

		cfg, err := s.Config()
		if err != nil {
			s.Close()
			continue
		}
		if cfg.StartType != mgr.StartAutomatic || hasStartTrigger(s) {
			s.Close()
			continue
		}
		displayName := name
		if cfg.DisplayName != "" {
			displayName = cfg.DisplayName
		}
		s.Close()

		if status.State != svc.Running || status.ProcessId == 0 {
			continue
		}
		c := &Container{
			ID:          containerID(KindService, name),
			Name:        name,
			DisplayName: displayName,
			Kind:        KindService,
			PID:         status.ProcessId,
		}
		c.PIDs = trees[c.PID]
		c.StartedAt = processStartTime(c.PID)
		out = append(out, c)
	}
	return out
}

type serviceTriggerInfo struct {
	cTriggers uint32
	pTriggers uintptr
	pReserved uintptr
}

func hasStartTrigger(s *mgr.Service) bool {
	var bytesNeeded uint32
	err := windows.QueryServiceConfig2(s.Handle, windows.SERVICE_CONFIG_TRIGGER_INFO, nil, 0, &bytesNeeded)
	if err != windows.ERROR_INSUFFICIENT_BUFFER || bytesNeeded == 0 {
		return false
	}
	buf := make([]byte, bytesNeeded)
	if err := windows.QueryServiceConfig2(s.Handle, windows.SERVICE_CONFIG_TRIGGER_INFO, &buf[0], bytesNeeded, &bytesNeeded); err != nil {
		return false
	}
	return (*serviceTriggerInfo)(unsafe.Pointer(&buf[0])).cTriggers > 0
}
