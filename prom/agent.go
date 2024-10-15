package prom

import (
	"time"

	"github.com/coroot/coroot-node-agent/common"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	promConfig "github.com/prometheus/common/config"
	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/config"
	"github.com/prometheus/prometheus/discovery/targetgroup"
	"github.com/prometheus/prometheus/scrape"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/storage/remote"
	"github.com/prometheus/prometheus/tsdb"
	"github.com/prometheus/prometheus/tsdb/agent"
	"k8s.io/klog/v2"
)

const (
	RemoteFlushDeadline = time.Minute
	jobName             = "coroot-node-agent"
	RemoteWriteTimeout  = 30 * time.Second
)

func StartAgent(machineId string) error {
	logger := level.NewFilter(Logger{}, level.AllowInfo())

	if *flags.MetricsEndpoint == nil {
		return nil
	}
	klog.Infoln("metrics remote write endpoint:", (*flags.MetricsEndpoint).String())
	cfg := config.DefaultConfig
	cfg.GlobalConfig.ScrapeInterval = model.Duration(*flags.ScrapeInterval)
	cfg.GlobalConfig.ScrapeTimeout = model.Duration(*flags.ScrapeInterval)
	cfg.RemoteWriteConfigs = append(cfg.RemoteWriteConfigs,
		&config.RemoteWriteConfig{
			URL:           &promConfig.URL{URL: *flags.MetricsEndpoint},
			Headers:       common.AuthHeaders(),
			RemoteTimeout: model.Duration(RemoteWriteTimeout),
			QueueConfig:   config.DefaultQueueConfig,
			HTTPClientConfig: promConfig.HTTPClientConfig{
				TLSConfig: promConfig.TLSConfig{InsecureSkipVerify: *flags.InsecureSkipVerify},
			},
		},
	)
	cfg.ScrapeConfigs = append(cfg.ScrapeConfigs, &config.ScrapeConfig{
		JobName:                 jobName,
		HonorLabels:             true,
		ScrapeClassicHistograms: true,
		MetricsPath:             "/metrics",
		Scheme:                  "http",
		EnableCompression:       false,
	})

	opts := agent.DefaultOptions()
	localStorage := &readyStorage{stats: tsdb.NewDBStats()}
	scraper := &readyScrapeManager{}
	remoteStorage := remote.NewStorage(logger, prometheus.DefaultRegisterer, localStorage.StartTime, *flags.WalDir, RemoteFlushDeadline, scraper)
	fanoutStorage := storage.NewFanout(logger, localStorage, remoteStorage)

	if err := remoteStorage.ApplyConfig(&cfg); err != nil {
		return err
	}

	scrapeManager, err := scrape.NewManager(nil, logger, fanoutStorage, prometheus.DefaultRegisterer)
	if err != nil {
		return err
	}
	if err = scrapeManager.ApplyConfig(&cfg); err != nil {
		return err
	}
	scraper.Set(scrapeManager)
	db, err := agent.Open(logger, prometheus.DefaultRegisterer, remoteStorage, *flags.WalDir, opts)
	if err != nil {
		return err
	}
	localStorage.Set(db, 0)
	db.SetWriteNotified(remoteStorage)

	tch := make(chan map[string][]*targetgroup.Group, 1)
	tch <- map[string][]*targetgroup.Group{
		jobName: {
			&targetgroup.Group{
				Targets: []model.LabelSet{
					{
						model.InstanceLabel: model.LabelValue(machineId),
						model.AddressLabel:  model.LabelValue(*flags.ListenAddress),
					},
				},
				Labels: model.LabelSet{model.JobLabel: jobName},
			},
		},
	}
	go func() {
		if err = scrapeManager.Run(tch); err != nil {
			klog.Errorln(err)
		}
	}()
	return nil
}
