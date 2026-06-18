package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

func main() {
	strict := flag.Bool("strict", false, "also fail when a metric family exists only in one scrape")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [--strict] <linux-scrape.prom> <windows-scrape.prom>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(2)
	}

	linux, err := loadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "load linux scrape: %v\n", err)
		os.Exit(1)
	}
	windows, err := loadFile(flag.Arg(1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "load windows scrape: %v\n", err)
		os.Exit(1)
	}

	result := compareMetricLabels(linux, windows, *strict)
	if len(result) > 0 {
		for _, line := range result {
			fmt.Fprintln(os.Stderr, line)
		}
		os.Exit(1)
	}
	fmt.Println("common metric label keys match")
}

func loadFile(path string) (map[string][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return loadMetricLabels(f)
}

func loadMetricLabels(r io.Reader) (map[string][]string, error) {
	parser := expfmt.TextParser{}
	families, err := parser.TextToMetricFamilies(r)
	if err != nil {
		return nil, err
	}
	res := map[string][]string{}
	for name, family := range families {
		labels := metricFamilyLabels(family)
		if len(labels) == 0 && len(family.Metric) == 0 {
			continue
		}
		res[name] = labels
	}
	return res, nil
}

func metricFamilyLabels(family *dto.MetricFamily) []string {
	seen := map[string]struct{}{}
	for _, metric := range family.Metric {
		for _, label := range metric.Label {
			seen[label.GetName()] = struct{}{}
		}
	}
	labels := make([]string, 0, len(seen))
	for label := range seen {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	return labels
}

func compareMetricLabels(left, right map[string][]string, strict bool) []string {
	var mismatches []string
	for _, name := range sortedKeys(left) {
		rightLabels, ok := right[name]
		if !ok {
			if strict {
				mismatches = append(mismatches, fmt.Sprintf("%s: missing from right scrape", name))
			}
			continue
		}
		leftLabels := left[name]
		if !sameStrings(leftLabels, rightLabels) {
			mismatches = append(mismatches, fmt.Sprintf(
				"%s: label keys differ: left=[%s] right=[%s]",
				name,
				strings.Join(leftLabels, ","),
				strings.Join(rightLabels, ","),
			))
		}
	}
	if strict {
		for _, name := range sortedKeys(right) {
			if _, ok := left[name]; !ok {
				mismatches = append(mismatches, fmt.Sprintf("%s: missing from left scrape", name))
			}
		}
	}
	return mismatches
}

func sortedKeys(values map[string][]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
