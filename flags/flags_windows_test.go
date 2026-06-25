//go:build windows

package flags

import (
	"net/url"
	"testing"
)

func TestWindowsPlatformEndpoints(t *testing.T) {
	oldTraces := *TracesEndpoint
	oldProfiles := *ProfilesEndpoint
	defer func() {
		*TracesEndpoint = oldTraces
		*ProfilesEndpoint = oldProfiles
	}()

	*TracesEndpoint = nil
	*ProfilesEndpoint = nil
	base, err := url.Parse("https://collector.example/base")
	if err != nil {
		t.Fatal(err)
	}
	platformEndpoints(base)

	if *TracesEndpoint == nil || (*TracesEndpoint).String() != "https://collector.example/base/v1/traces" {
		t.Fatalf("TracesEndpoint=%v, want https://collector.example/base/v1/traces", *TracesEndpoint)
	}
	if *ProfilesEndpoint == nil || (*ProfilesEndpoint).String() != "https://collector.example/base/v1/profiles" {
		t.Fatalf("ProfilesEndpoint=%v, want https://collector.example/base/v1/profiles", *ProfilesEndpoint)
	}
}

func TestWindowsPlatformEndpointsPreserveExplicitValues(t *testing.T) {
	oldTraces := *TracesEndpoint
	oldProfiles := *ProfilesEndpoint
	defer func() {
		*TracesEndpoint = oldTraces
		*ProfilesEndpoint = oldProfiles
	}()

	traces, _ := url.Parse("https://traces.example/custom")
	profiles, _ := url.Parse("https://profiles.example/custom")
	*TracesEndpoint = traces
	*ProfilesEndpoint = profiles
	base, err := url.Parse("https://collector.example/base")
	if err != nil {
		t.Fatal(err)
	}
	platformEndpoints(base)

	if (*TracesEndpoint).String() != traces.String() {
		t.Fatalf("TracesEndpoint=%v, want preserved %s", *TracesEndpoint, traces)
	}
	if (*ProfilesEndpoint).String() != profiles.String() {
		t.Fatalf("ProfilesEndpoint=%v, want preserved %s", *ProfilesEndpoint, profiles)
	}
}
