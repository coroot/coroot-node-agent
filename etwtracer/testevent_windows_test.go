//go:build windows

package etwtracer

import "github.com/0xrawsec/golang-etw/etw"

func NewTestEvent(eventID uint16, properties map[string]interface{}) *etw.Event {
	e := etw.NewEvent()
	e.System.Provider.Name = "Microsoft-Windows-Kernel-Network"
	e.System.EventID = eventID
	e.EventData = properties
	return e
}
