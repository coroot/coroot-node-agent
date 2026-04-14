package common

import (
	"crypto/tls"
	"crypto/x509"
	"os"

	"github.com/coroot/coroot-node-agent/flags"
	"k8s.io/klog/v2"
)

func AuthHeaders() map[string]string {
	res := map[string]string{}
	if apiKey := *flags.ApiKey; apiKey != "" {
		res["X-Api-Key"] = apiKey
	}
	return res
}

func TlsConfig() *tls.Config {
	cfg := &tls.Config{InsecureSkipVerify: *flags.InsecureSkipVerify}
	if *flags.CAFile != "" {
		ca, err := os.ReadFile(*flags.CAFile)
		if err != nil {
			klog.Fatalln(err)
			return cfg
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			klog.Warningln("failed to load system cert pool, starting with empty pool:", err)
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(ca) {
			klog.Fatalf("failed to parse CA from %s", *flags.CAFile)
		}
		cfg.RootCAs = pool
	}
	return cfg
}
