package logs

import (
	"bufio"
	"context"
	"github.com/coroot/logparser"
	"io"
	"k8s.io/klog/v2"
	"os"
	"strings"
	"time"
)

var (
	tailPollInterval = time.Second
)

type TailReader struct {
	fileName string
	ch       chan<- logparser.LogEntry

	file   *os.File
	info   os.FileInfo
	reader *bufio.Reader

	stop    context.CancelFunc
	stopped chan struct{}
}

func NewTailReader(fileName string, ch chan<- logparser.LogEntry) (*TailReader, error) {
	ctx, cancel := context.WithCancel(context.Background())
	r := &TailReader{
		fileName: fileName,
		ch:       ch,
		stop:     cancel,
		stopped:  make(chan struct{}),
	}
	var err error
	if r.file, err = os.Open(fileName); err != nil {
		return nil, err
	}
	if r.info, err = r.file.Stat(); err != nil {
		return nil, err
	}
	if _, err = r.file.Seek(0, io.SeekEnd); err != nil {
		return nil, err
	}
	r.reader = bufio.NewReader(r.file)

	go func() {
		var prefix string
		for {
			select {
			case <-ctx.Done():
				r.stopped <- struct{}{}
				return
			default:
				line, err := r.reader.ReadString('\n')
				if err != nil {
					prefix = line
					r.poll(ctx)
					continue
				}
				if prefix != "" {
					line = prefix + line
					prefix = ""
				}
				r.ch <- logparser.LogEntry{
					Timestamp: time.Now(),
					Content:   strings.TrimSuffix(line, "\n"),
					Level:     logparser.LevelUnknown,
				}
			}
		}
	}()

	return r, nil
}

func (r *TailReader) Stop() {
	klog.Infoln("stopping tail reader for", r.fileName)
	r.stop()
	<-r.stopped
	if r.file != nil {
		_ = r.file.Close()
	}
}

func (r *TailReader) poll(ctx context.Context) {
	ticker := time.NewTicker(tailPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if info, err := os.Stat(r.fileName); err != nil {
				if r.file != nil {
					_ = r.file.Close()
					r.file = nil
				}
			} else {
				if r.file == nil {
					f, err := os.Open(r.fileName)
					if err != nil {
						continue
					}
					r.file = f
					r.info = info
					r.reader = bufio.NewReader(r.file)
					return
				}
				if r.moved(info) || r.truncated(info) || r.appended(info) {
					r.info = info
					return
				}
			}
		}
	}
}

func (r *TailReader) moved(info os.FileInfo) bool {
	if !os.SameFile(r.info, info) {
		f, err := os.Open(r.fileName)
		if err != nil {
			r.file = nil
			return false
		}
		_ = r.file.Close()
		r.file = f
		r.reader = bufio.NewReader(r.file)
		return true
	}
	return false
}

func (r *TailReader) truncated(info os.FileInfo) bool {
	if r.file == nil {
		return false
	}
	if info.Size() < r.info.Size() {
		if _, err := r.file.Seek(0, io.SeekStart); err == nil {
			return true
		}
	}
	return false
}

func (r *TailReader) appended(info os.FileInfo) bool {
	if r.file == nil {
		return false
	}
	if info.Size() > r.info.Size() {
		return true
	}
	return false
}
