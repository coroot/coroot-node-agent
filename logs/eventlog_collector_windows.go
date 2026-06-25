//go:build windows

package logs

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/logparser"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

const eventLogUnknown = "unknown"

var windowsEventLogMessagesDesc = prometheus.NewDesc(
	"windows_event_log_messages_total",
	"Number of Windows Event Log messages grouped by the automatically extracted repeated pattern",
	[]string{"channel", "provider", "event_id", "level", "pattern_hash", "sample"},
	nil,
)

type eventLogPoller interface {
	Poll() []LogEntry
	Close()
}

type EventLogCollector struct {
	lock             sync.Mutex
	poller           eventLogPoller
	multilineTimeout time.Duration
	parsers          map[eventLogSource]*eventLogParser
}

type eventLogSource struct {
	channel  string
	provider string
	eventID  uint32
}

type eventLogParser struct {
	source eventLogSource
	ch     chan logparser.LogEntry
	parser *logparser.Parser
}

func NewEventLogCollector(channels []string) (*EventLogCollector, error) {
	channels = normalizeEventLogChannels(channels)
	reader, err := NewEventLogReader(channels...)
	if err != nil {
		return nil, err
	}
	return newEventLogCollector(reader, MultilineCollectorTimeout), nil
}

func newEventLogCollector(poller eventLogPoller, multilineTimeout time.Duration) *EventLogCollector {
	return &EventLogCollector{
		poller:           poller,
		multilineTimeout: multilineTimeout,
		parsers:          map[eventLogSource]*eventLogParser{},
	}
}

func (c *EventLogCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- windowsEventLogMessagesDesc
}

func (c *EventLogCollector) Collect(ch chan<- prometheus.Metric) {
	c.lock.Lock()
	defer c.lock.Unlock()

	for _, entry := range c.poller.Poll() {
		c.addEntry(entry)
	}
	for _, parser := range c.parsers {
		for _, counter := range parser.parser.GetCounters() {
			ch <- prometheus.MustNewConstMetric(
				windowsEventLogMessagesDesc,
				prometheus.CounterValue,
				float64(counter.Messages),
				parser.source.channel,
				parser.source.provider,
				strconv.FormatUint(uint64(parser.source.eventID), 10),
				counter.Level.String(),
				counter.Hash,
				common.TruncateUtf8(counter.Sample, *flags.MaxLabelLength),
			)
		}
	}
}

func (c *EventLogCollector) Close() {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.poller.Close()
	for source, parser := range c.parsers {
		parser.parser.Stop()
		delete(c.parsers, source)
	}
}

func (c *EventLogCollector) addEntry(entry LogEntry) {
	if strings.TrimSpace(entry.Message) == "" {
		return
	}
	source := sourceForEvent(entry)
	parser := c.parsers[source]
	if parser == nil {
		parser = newEventLogParser(source, c.multilineTimeout)
		c.parsers[source] = parser
		klog.InfoS("started Windows Event Log parser", "channel", source.channel, "provider", source.provider, "event_id", source.eventID)
	}
	select {
	case parser.ch <- logparser.LogEntry{Timestamp: entry.Timestamp, Content: entry.Message, Level: entry.Level}:
	default:
		klog.Warningf("dropping Windows Event Log entry because parser queue is full: channel=%s provider=%s event_id=%d", source.channel, source.provider, source.eventID)
	}
}

func newEventLogParser(source eventLogSource, multilineTimeout time.Duration) *eventLogParser {
	ch := make(chan logparser.LogEntry, 1024)
	return &eventLogParser{
		source: source,
		ch:     ch,
		parser: logparser.NewParser(ch, nil, EventLogEmitter(source.channel, source.provider, source.eventID), multilineTimeout, *flags.LogPatternsPerContainer),
	}
}

func sourceForEvent(entry LogEntry) eventLogSource {
	return eventLogSource{
		channel:  nonEmpty(entry.Channel),
		provider: nonEmpty(entry.Provider),
		eventID:  entry.EventID,
	}
}

func nonEmpty(s string) string {
	if s = strings.TrimSpace(s); s != "" {
		return s
	}
	return eventLogUnknown
}

func normalizeEventLogChannels(channels []string) []string {
	res := make([]string, 0, len(channels))
	seen := map[string]bool{}
	for _, channel := range channels {
		channel = strings.TrimSpace(channel)
		if channel == "" || seen[channel] {
			continue
		}
		seen[channel] = true
		res = append(res, channel)
	}
	if len(res) == 0 {
		return []string{"Application", "System"}
	}
	return res
}
