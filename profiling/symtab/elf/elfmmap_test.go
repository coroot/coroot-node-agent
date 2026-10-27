package elf

import (
	"debug/elf"
	"slices"
	"strings"
	"testing"

	"github.com/coroot/coroot-node-agent/profiling/testutil"

	"github.com/stretchr/testify/require"
)

func TestElfSymbolComparison(t *testing.T) {
	testutil.RequireTestdata(t, elfTestdata)
	testOneElfFile := func(t *testing.T, f string) {
		e, err := elf.Open(f)
		require.NoError(t, err)
		defer e.Close()

		genuineSymbols := GetELFSymbolsFromSymtab(e)

		me, err := NewMMapedElfFile(f)
		require.NoError(t, err)
		defer me.Close()

		tab, _ := me.NewSymbolTable(new(SymbolsOptions))
		if tab == nil {
			tab = &SymbolTable{}
		}
		var mySymbols []TestSym

		require.Equal(t, len(genuineSymbols), len(tab.Index.Names))
		for i, symbol := range genuineSymbols {
			require.Equal(t, symbol.Start, tab.Index.Values.Value(i))
			name, _ := tab.symbolName(i)
			mySymbols = append(mySymbols, TestSym{
				Name:  name,
				Start: symbol.Start,
			})
		}

		cmp := func(a, b TestSym) int {
			if a.Start == b.Start {
				return strings.Compare(a.Name, b.Name)
			} else if a.Start < b.Start {
				return -1
			} else {
				return 1
			}
		}
		slices.SortFunc(mySymbols, cmp)
		slices.SortFunc(genuineSymbols, cmp)
		require.Equal(t, genuineSymbols, mySymbols)
	}

	fs := []string{
		"../../testdata/elf/elfs/elf",
		"../../testdata/elf/elfs/elf.debug",
		"../../testdata/elf/elfs/elf.nopie",
		"../../testdata/elf/elfs/libexample.so",
		"../../testdata/elf/elfs/go12",
		"../../testdata/elf/elfs/go16",
		"../../testdata/elf/elfs/go18",
		"../../testdata/elf/elfs/go20",
		"../../testdata/elf/elfs/go12-static",
		"../../testdata/elf/elfs/go16-static",
		"../../testdata/elf/elfs/go18-static",
		"../../testdata/elf/elfs/go20-static",
	}
	for _, f := range fs {
		t.Run(f, func(t *testing.T) {
			testOneElfFile(t, f)
		})
	}
}
