package logs

import (
	"github.com/coroot/logparser"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func TestTailReader(t *testing.T) {
	f, err := ioutil.TempFile("/tmp", "log")
	assert.NoError(t, err)
	defer os.Remove(f.Name())

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
		time.Sleep(3 * tailPollInterval)
	}

	get := func(expected string) {
		entry := <-ch
		assert.Equal(t, expected, entry.Content)
	}

	write("foo 1\n")
	get("foo 1")

	// append
	write("bar 1\nbuz 1\n")
	get("bar 1")
	get("buz 1")

	// no end of line
	write("foo 2\nba")
	wait()
	write("r 2\n")
	get("foo 2")
	get("bar 2")

	// move
	err = os.Rename(f.Name(), f.Name()+".1")
	assert.NoError(t, err)
	defer os.Remove(f.Name() + ".1")
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
