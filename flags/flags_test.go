package flags

import "testing"

func TestIsGoTestBinary(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{name: "/tmp/logs.test", want: true},
		{name: `C:\Temp\logs.test.exe`, want: true},
		{name: `C:\Temp\coroot-node-agent.exe`, want: false},
		{name: "/usr/bin/coroot-node-agent", want: false},
	}
	for _, tc := range cases {
		if got := isGoTestBinary(tc.name); got != tc.want {
			t.Fatalf("isGoTestBinary(%q)=%v, want %v", tc.name, got, tc.want)
		}
	}
}
