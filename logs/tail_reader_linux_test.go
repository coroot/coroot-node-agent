//go:build linux

package logs

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coroot/logparser"
	"github.com/stretchr/testify/assert"
)

func TestTailReaderRotationAndReopen(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "log")
	assert.NoError(t, err)

	tailPollInterval = time.Millisecond * 100
	ch := make(chan logparser.LogEntry, 10)
	tr, err := NewTailReader(f.Name(), ch)
	assert.NoError(t, err)
	defer tr.Stop()

	write := func(s string) {
		_, err = f.WriteString(s)
		assert.NoError(t, err)
	}

	wait := func() {
		time.Sleep(time.Second)
	}

	get := func(expected string) {
		entry := <-ch
		assert.Equal(t, expected, entry.Content)
	}

	write("foo 1\n")
	get("foo 1")

	// move
	rotated := filepath.Join(filepath.Dir(f.Name()), filepath.Base(f.Name())+".1")
	err = os.Rename(f.Name(), rotated)
	assert.NoError(t, err)
	f, err = os.Create(f.Name())
	assert.NoError(t, err)
	write("foo 3\nbar 3\n")
	get("foo 3")
	get("bar 3")

	// truncate
	f, err = os.OpenFile(f.Name(), os.O_WRONLY|os.O_TRUNC, 0)
	assert.NoError(t, err)
	write("foo 4\n")
	get("foo 4")

	// delete
	err = os.Remove(f.Name())
	assert.NoError(t, err)
	wait()
	f, err = os.Create(f.Name())
	assert.NoError(t, err)
	write("foo 5\n")
	get("foo 5")
}
