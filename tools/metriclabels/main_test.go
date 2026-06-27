package main

import (
	"strings"
	"testing"
)

func TestCompareMetricLabelsMatchesCommonFamilies(t *testing.T) {
	left, err := loadMetricLabels(strings.NewReader(`
# HELP node_info Meta information
# TYPE node_info gauge
node_info{hostname="linux",kernel_version="6.1"} 1
# HELP linux_only Linux only
# TYPE linux_only gauge
linux_only{foo="bar"} 1
`))
	if err != nil {
		t.Fatal(err)
	}
	right, err := loadMetricLabels(strings.NewReader(`
# HELP node_info Meta information
# TYPE node_info gauge
node_info{hostname="windows",kernel_version="Windows 10.0.26100"} 1
`))
	if err != nil {
		t.Fatal(err)
	}
	if mismatches := compareMetricLabels(left, right, false); len(mismatches) != 0 {
		t.Fatalf("unexpected mismatches: %v", mismatches)
	}
}

func TestCompareMetricLabelsFindsMismatchedKeys(t *testing.T) {
	left, err := loadMetricLabels(strings.NewReader(`
# TYPE container_info gauge
container_info{container_id="/docker/a",app_id="",image="a"} 1
`))
	if err != nil {
		t.Fatal(err)
	}
	right, err := loadMetricLabels(strings.NewReader(`
# TYPE container_info gauge
container_info{container_id="/docker/a",image="a"} 1
`))
	if err != nil {
		t.Fatal(err)
	}
	if mismatches := compareMetricLabels(left, right, false); len(mismatches) != 1 {
		t.Fatalf("mismatches=%v, want one mismatch", mismatches)
	}
}

func TestCompareMetricLabelsStrictFindsMissingFamilies(t *testing.T) {
	left := map[string][]string{"a": nil}
	right := map[string][]string{"b": nil}
	if mismatches := compareMetricLabels(left, right, true); len(mismatches) != 2 {
		t.Fatalf("mismatches=%v, want two missing-family mismatches", mismatches)
	}
}
