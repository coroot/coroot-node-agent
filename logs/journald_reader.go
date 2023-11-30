package logs

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-systemd/v22/sdjournal"
	"github.com/coroot/logparser"
	"k8s.io/klog/v2"
)

type JournaldReader struct {
	journal     *sdjournal.Journal
	subscribers map[string]chan<- logparser.LogEntry
	until       chan time.Time
	lock        sync.Mutex
}

func NewJournaldReader(journalPaths ...string) (*JournaldReader, error) {
	r := &JournaldReader{
		until:       make(chan time.Time),
		subscribers: map[string]chan<- logparser.LogEntry{},
	}
	var err error
	for _, journalPath := range journalPaths {
		if r.journal, err = sdjournal.NewJournalFromDir(journalPath); err != nil {
			continue
		}
		usage, err := r.journal.GetUsage()
		if err != nil {
			continue
		}
		if usage == 0 {
			r.journal = nil
			continue
		}
		if err = r.journal.SeekRealtimeUsec(uint64(time.Now().Add(time.Millisecond).UnixNano() / 1000)); err != nil {
			return nil, err
		}
		//klog.Infof("systemd journal found in %s", journalPath)
		break
	}
	if r.journal == nil {
		return nil, fmt.Errorf("systemd journal not found in %s", strings.Join(journalPaths, ","))
	}
	go r.follow()
	return r, nil
}

func (r *JournaldReader) follow() {
	for {
		c, err := r.journal.Next()
		if err != nil {
			klog.Errorln("failed to read journal:", err)
			return
		}
		if c <= 0 {
			r.journal.Wait(time.Millisecond * 100)
			continue
		}
		e, err := r.journal.GetEntry()
		if err != nil {
			klog.Errorf("failed to read entry from journal")
			return
		}
		msg := e.Fields[sdjournal.SD_JOURNAL_FIELD_MESSAGE]
		if msg == "" {
			continue
		}
		le := logparser.LogEntry{
			Timestamp: time.UnixMicro(int64(e.RealtimeTimestamp)),
			Content:   msg,
			Level:     logparser.LevelByPriority(e.Fields[sdjournal.SD_JOURNAL_FIELD_PRIORITY]),
		}
		r.lock.Lock()
		ch, ok := r.subscribers[e.Fields[sdjournal.SD_JOURNAL_FIELD_SYSTEMD_CGROUP]]
		r.lock.Unlock()
		if !ok {
			continue
		}
		ch <- le
	}
}

func (r *JournaldReader) Subscribe(cgroup string, ch chan<- logparser.LogEntry) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	if _, ok := r.subscribers[cgroup]; ok {
		return fmt.Errorf(`duplicate subscriber for cgroup %s`, cgroup)
	}
	r.subscribers[cgroup] = ch
	return nil
}

func (r *JournaldReader) Unsubscribe(cgroup string) {
	r.lock.Lock()
	defer r.lock.Unlock()
	if _, ok := r.subscribers[cgroup]; !ok {
		klog.Warning("unknown subscriber for cgroup", cgroup)
		return
	}
	delete(r.subscribers, cgroup)
}

func (r *JournaldReader) Close() {
	_ = r.journal.Close()
}
