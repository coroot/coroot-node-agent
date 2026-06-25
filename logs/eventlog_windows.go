//go:build windows

package logs

import (
	"encoding/xml"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coroot/logparser"
	"github.com/google/winops/winlog"
	"github.com/google/winops/winlog/wevtapi"
	"golang.org/x/sys/windows"
	"k8s.io/klog/v2"
)

const eventLogLocaleEn = 1033

type EventLogReader struct {
	mu           sync.Mutex
	buf          []LogEntry
	config       *winlog.SubscribeConfig
	subscription windows.Handle
	pubCache     map[string]windows.Handle
	stop         windows.Handle
}

func NewEventLogReader(channels ...string) (*EventLogReader, error) {
	signal, err := windows.CreateEvent(nil, 1, 1, nil)
	if err != nil {
		return nil, err
	}
	stop, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		windows.CloseHandle(signal)
		return nil, err
	}

	xpaths := make(map[string]string, len(channels))
	for _, ch := range channels {
		xpaths[ch] = "*"
	}
	xmlQuery, err := winlog.BuildStructuredXMLQuery(xpaths)
	if err != nil {
		return nil, err
	}
	queryPtr, err := syscall.UTF16PtrFromString(string(xmlQuery))
	if err != nil {
		return nil, err
	}

	cfg := &winlog.SubscribeConfig{
		SignalEvent: signal,
		Query:       queryPtr,
		Flags:       wevtapi.EvtSubscribeToFutureEvents,
	}
	subscription, err := winlog.Subscribe(cfg)
	if err != nil {
		cfg.Close()
		windows.CloseHandle(stop)
		return nil, err
	}

	r := &EventLogReader{
		config:       cfg,
		subscription: subscription,
		pubCache:     map[string]windows.Handle{},
		stop:         stop,
	}
	klog.Infof("subscribed to event log channels: %v", channels)
	go r.consume()
	return r, nil
}

func (r *EventLogReader) consume() {
	handles := []windows.Handle{r.stop, r.config.SignalEvent}
	for {
		ev, err := windows.WaitForMultipleObjects(handles, false, windows.INFINITE)
		if err != nil || ev == windows.WAIT_OBJECT_0 {
			return
		}
		for {
			events, err := winlog.GetRenderedEvents(r.config, r.pubCache, r.subscription, 64, eventLogLocaleEn)
			for _, x := range events {
				if entry, ok := parseEvent(x); ok {
					r.mu.Lock()
					r.buf = append(r.buf, entry)
					r.mu.Unlock()
				}
			}
			if err != nil {
				break
			}
		}
		windows.ResetEvent(r.config.SignalEvent)
	}
}

func (r *EventLogReader) Poll() []LogEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	entries := r.buf
	r.buf = nil
	return entries
}

func (r *EventLogReader) Close() {
	windows.SetEvent(r.stop)
	winlog.Close(r.subscription)
	for _, h := range r.pubCache {
		winlog.Close(h)
	}
	r.config.Close()
	windows.CloseHandle(r.stop)
}

type LogEntry struct {
	Timestamp time.Time
	Channel   string
	Provider  string
	EventID   uint32
	PID       uint32
	Level     logparser.Level
	Message   string
}

type renderedEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     uint32 `xml:"EventID"`
		Level       uint64 `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Execution struct {
			ProcessID uint32 `xml:"ProcessID,attr"`
		} `xml:"Execution"`
		Channel string `xml:"Channel"`
	} `xml:"System"`
	EventData struct {
		Data []string `xml:"Data"`
	} `xml:"EventData"`
	RenderingInfo struct {
		Message string `xml:"Message"`
	} `xml:"RenderingInfo"`
}

func parseEvent(x string) (LogEntry, bool) {
	var re renderedEvent
	if err := xml.Unmarshal([]byte(x), &re); err != nil {
		return LogEntry{}, false
	}
	msg := strings.TrimSpace(re.RenderingInfo.Message)
	if msg == "" {
		msg = strings.TrimSpace(strings.Join(re.EventData.Data, " "))
	}
	if msg == "" {
		return LogEntry{}, false
	}
	ts, err := time.Parse(time.RFC3339Nano, re.System.TimeCreated.SystemTime)
	if err != nil {
		ts = time.Now()
	}
	return LogEntry{
		Timestamp: ts,
		Channel:   re.System.Channel,
		Provider:  re.System.Provider.Name,
		EventID:   re.System.EventID,
		PID:       re.System.Execution.ProcessID,
		Level:     winLevelToLogparser(re.System.Level),
		Message:   msg,
	}, true
}

func winLevelToLogparser(level uint64) logparser.Level {
	switch level {
	case 1:
		return logparser.LevelCritical
	case 2:
		return logparser.LevelError
	case 3:
		return logparser.LevelWarning
	case 5:
		return logparser.LevelDebug
	default:
		return logparser.LevelInfo
	}
}
