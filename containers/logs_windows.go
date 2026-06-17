//go:build windows

package containers

import (
	"sync"
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/coroot-node-agent/logs"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/coroot/logparser"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"
)

const (
	windowsContainerLogSource        = "stdout/stderr"
	windowsMultilineCollectorTimeout = time.Second
)

var (
	windowsContainerLogMessagesDesc = prometheus.NewDesc(
		"container_log_messages_total",
		"Number of messages grouped by the automatically extracted repeated pattern",
		[]string{"container_id", "app_id", "source", "level", "pattern_hash", "sample"}, nil,
	)
)

type windowsContainerLogState struct {
	lock    sync.Mutex
	parsers map[ContainerID]*windowsContainerLogParser
}

type windowsContainerLogParser struct {
	containerID ContainerID
	appID       string
	logPath     string
	parser      *logparser.Parser
	stop        func()
}

func newWindowsContainerLogState() *windowsContainerLogState {
	return &windowsContainerLogState{parsers: map[ContainerID]*windowsContainerLogParser{}}
}

func (s *windowsContainerLogState) Describe(ch chan<- *prometheus.Desc) {
	ch <- windowsContainerLogMessagesDesc
}

func (s *windowsContainerLogState) Sync(containers []windowsContainer) {
	if *flags.DisableLogParsing {
		s.Close()
		return
	}

	desired := map[ContainerID]windowsContainer{}
	for _, c := range containers {
		if c.ID == "" || c.LogPath == "" || c.LogDecoder == nil {
			continue
		}
		desired[c.ID] = c
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	for id, parser := range s.parsers {
		c, ok := desired[id]
		if !ok || c.LogPath != parser.logPath || c.AppID != parser.appID {
			parser.Stop()
			delete(s.parsers, id)
		}
	}
	for id, c := range desired {
		if s.parsers[id] != nil {
			continue
		}
		parser, err := newWindowsContainerLogParser(c)
		if err != nil {
			klog.Warningf("failed to start Windows container log parser for %s: %s", c.ID, err)
			continue
		}
		s.parsers[id] = parser
	}
}

func (s *windowsContainerLogState) Collect(ch chan<- prometheus.Metric) {
	s.lock.Lock()
	defer s.lock.Unlock()

	for _, parser := range s.parsers {
		for _, counter := range parser.parser.GetCounters() {
			ch <- prometheus.MustNewConstMetric(
				windowsContainerLogMessagesDesc,
				prometheus.CounterValue,
				float64(counter.Messages),
				string(parser.containerID),
				parser.appID,
				windowsContainerLogSource,
				counter.Level.String(),
				counter.Hash,
				common.TruncateUtf8(counter.Sample, *flags.MaxLabelLength),
			)
		}
	}
}

func (s *windowsContainerLogState) Close() {
	s.lock.Lock()
	defer s.lock.Unlock()

	for id, parser := range s.parsers {
		parser.Stop()
		delete(s.parsers, id)
	}
}

func newWindowsContainerLogParser(c windowsContainer) (*windowsContainerLogParser, error) {
	ch := make(chan logparser.LogEntry)
	parser := logparser.NewParser(ch, c.LogDecoder, logs.OtelLogEmitter(string(c.ID)), windowsMultilineCollectorTimeout, *flags.LogPatternsPerContainer)
	reader, err := logs.NewTailReader(proc.HostPath(c.LogPath), ch)
	if err != nil {
		parser.Stop()
		return nil, err
	}
	klog.InfoS("started Windows container logparser", "container_id", c.ID, "log", c.LogPath)
	return &windowsContainerLogParser{
		containerID: c.ID,
		appID:       c.AppID,
		logPath:     c.LogPath,
		parser:      parser,
		stop:        reader.Stop,
	}, nil
}

func (p *windowsContainerLogParser) Stop() {
	if p.stop != nil {
		p.stop()
	}
	p.parser.Stop()
}
