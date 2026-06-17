//go:build windows

package main

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

func TestWindowsServiceStopCancelsRun(t *testing.T) {
	cancelled := make(chan struct{})
	service := newWindowsService(func(ctx context.Context) error {
		<-ctx.Done()
		close(cancelled)
		return nil
	})
	requests := make(chan svc.ChangeRequest)
	statuses := make(chan svc.Status, 4)
	done := make(chan uint32, 1)
	go func() {
		_, code := service.Execute(nil, requests, statuses)
		done <- code
	}()

	expectStatus(t, statuses, svc.StartPending)
	running := expectStatus(t, statuses, svc.Running)
	if running.Accepts != windowsServiceAccepts {
		t.Fatalf("Accepts=%v, want %v", running.Accepts, windowsServiceAccepts)
	}

	requests <- svc.ChangeRequest{Cmd: svc.Interrogate}
	interrogated := expectStatus(t, statuses, svc.Running)
	if interrogated.Accepts != windowsServiceAccepts {
		t.Fatalf("interrogated Accepts=%v, want %v", interrogated.Accepts, windowsServiceAccepts)
	}

	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	expectStatus(t, statuses, svc.StopPending)

	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("service stop did not cancel run context")
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit code=%d, want 0", code)
		}
	case <-time.After(time.Second):
		t.Fatal("service handler did not return")
	}
}

func expectStatus(t *testing.T, statuses <-chan svc.Status, state svc.State) svc.Status {
	t.Helper()
	select {
	case status := <-statuses:
		if status.State != state {
			t.Fatalf("status=%v, want %v", status.State, state)
		}
		return status
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for status %v", state)
		return svc.Status{}
	}
}
