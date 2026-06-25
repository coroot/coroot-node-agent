//go:build windows

package main

import (
	"strings"

	"golang.org/x/sys/windows/svc/eventlog"
)

type eventLogWriter struct {
	log *eventlog.Log
}

func newEventLogWriter(source string) (*eventLogWriter, error) {
	_ = eventlog.InstallAsEventCreate(source, eventlog.Info|eventlog.Warning|eventlog.Error)

	log, err := eventlog.Open(source)
	if err != nil {
		return nil, err
	}
	return &eventLogWriter{log: log}, nil
}

func (w *eventLogWriter) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	if msg == "" {
		return len(p), nil
	}

	if len(msg) > 0 {
		switch msg[0] {
		case 'W':
			w.log.Warning(1, msg)
		case 'E', 'F':
			w.log.Error(1, msg)
		default:
			w.log.Info(1, msg)
		}
	}
	return len(p), nil
}
