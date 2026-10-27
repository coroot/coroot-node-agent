package elf

import (
	"strings"
	"testing"

	"github.com/coroot/coroot-node-agent/profiling/testutil"

	"github.com/stretchr/testify/require"
)

func TestSelfGoSymbolComparison(t *testing.T) {
	testutil.RequireTestdata(t, elfTestdata)
	testGoSymbolTable := func(t *testing.T, expectedSymbols []TestSym, goTable *GoTable) {
		for _, symbol := range expectedSymbols {
			name := goTable.Resolve(symbol.Start)
			require.Equal(t, symbol.Name, name)
		}

		first := goTable.Index.Entry.First()
		name := goTable.Resolve(first - 1)
		require.Empty(t, name)
		name = goTable.Resolve(goTable.Index.End)
		require.Empty(t, name)
		name = goTable.Resolve(goTable.Index.End + 1)
		require.Empty(t, name)
	}

	ts := []struct {
		f        string
		expect32 bool
	}{
		{"../../testdata/elf/elfs/go12", true},
		{"../../testdata/elf/elfs/go16", true},
		{"../../testdata/elf/elfs/go18", true},
		{"../../testdata/elf/elfs/go20", true},
		{"../../testdata/elf/elfs/go12-static", true},
		{"../../testdata/elf/elfs/go16-static", false}, // this one switches from 32 to 64 in the middle
		{"../../testdata/elf/elfs/go18-static", false}, // this one starts with 64
		{"../../testdata/elf/elfs/go20-static", true},
		{"../../testdata/elf/elfs/go26", true},        // Go 1.26: pcHeader.textStart is always zero
		{"../../testdata/elf/elfs/go26-static", true}, // Go 1.26: static build
		{"../../testdata/elf/elfs/go26-cgo", true},    // Go 1.26 + cgo, externally linked: runtime.text != .text.Addr
	}
	for _, testcase := range ts {
		t.Run(testcase.f, func(t *testing.T) {
			patchGo20Magic := strings.Contains(testcase.f, "go20")
			expectedSymbols, err := GetGoSymbols(testcase.f, patchGo20Magic)

			require.NoError(t, err)

			me, err := NewMMapedElfFile(testcase.f)
			require.NoError(t, err)
			defer me.Close()

			goTable, err := me.NewGoTable()

			require.NoError(t, err)
			require.Equal(t, testcase.expect32, goTable.Index.Entry.Is32())

			require.Greater(t, len(expectedSymbols), 1000)

			testGoSymbolTable(t, expectedSymbols, goTable)

			if testcase.expect32 {
				goTable2 := &GoTable{}
				*goTable2 = *goTable
				goTable2.Index.Entry = goTable2.Index.Entry.PCIndex64()

				require.False(t, goTable2.Index.Entry.Is32())
				testGoSymbolTable(t, expectedSymbols, goTable)
			}
		})
	}
}
