//go:build windows

package main

import (
	"context"

	"golang.org/x/sys/windows/svc"
	"k8s.io/klog/v2"
)

const windowsServiceAccepts = svc.AcceptStop | svc.AcceptShutdown

type windowsService struct {
	run func(context.Context) error
}

func newWindowsService(run func(context.Context) error) *windowsService {
	return &windowsService{run: run}
}

func (s *windowsService) Execute(args []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.run(ctx)
	}()

	running := svc.Status{State: svc.Running, Accepts: windowsServiceAccepts}
	statuses <- running

	for {
		select {
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				statuses <- running
			case svc.Stop, svc.Shutdown:
				statuses <- svc.Status{State: svc.StopPending}
				cancel()
				if err := <-errCh; err != nil {
					klog.Errorf("Windows service stopped with error: %s", err)
					return false, 1
				}
				return false, 0
			default:
				klog.Warningf("unexpected Windows service control request: %v", request.Cmd)
			}
		case err := <-errCh:
			if err != nil {
				klog.Errorf("Windows service exited with error: %s", err)
				return false, 1
			}
			return false, 0
		}
	}
}
