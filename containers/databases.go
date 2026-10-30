package containers

import (
	"fmt"
	"net"
	"os"
	"time"

	cacommon "github.com/coroot/coroot-cluster-agent/common"
	"github.com/coroot/coroot-cluster-agent/metrics/dbtracker"
	"github.com/coroot/coroot-cluster-agent/metrics/exporter"
	"github.com/coroot/coroot-node-agent/flags"
	"github.com/coroot/logger"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v2"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
)

const (
	dbReconcileInterval = 10 * time.Second
	dbMaxTablesPerDB    = 1000
	dbMinCollectTimeout = time.Second
)

var dbTypes = map[exporter.Type]bool{
	exporter.TypePostgres:  true,
	exporter.TypeMysql:     true,
	exporter.TypeRedis:     true,
	exporter.TypeMongodb:   true,
	exporter.TypeMemcached: true,
}

type DatabaseCredentials struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type DatabaseConfig struct {
	Type        string              `yaml:"type"`
	Host        string              `yaml:"host"`
	Port        string              `yaml:"port"`
	Credentials DatabaseCredentials `yaml:"credentials"`
	Params      map[string]string   `yaml:"params"`
}

type agentConfig struct {
	Databases []DatabaseConfig `yaml:"databases"`
}

type dbTarget struct {
	cfg  DatabaseConfig
	addr netaddr.IPPort

	containerId ContainerID
	exporter    *exporter.Exporter
	missing     bool
}

func (t *dbTarget) String() string {
	return fmt.Sprintf("%s://%s", t.cfg.Type, t.addr)
}

func loadDatabaseTargets(path string) ([]*dbTarget, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			klog.Infof("config file %s not found, no databases to monitor", path)
			return nil, nil
		}
		return nil, err
	}
	var cfg agentConfig
	if err = yaml.Unmarshal([]byte(os.ExpandEnv(string(data))), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	var res []*dbTarget
	for i, d := range cfg.Databases {
		if !dbTypes[exporter.Type(d.Type)] {
			return nil, fmt.Errorf("invalid %s: databases[%d]: unsupported type %q", path, i, d.Type)
		}
		if d.Host == "" || d.Port == "" {
			return nil, fmt.Errorf("invalid %s: databases[%d]: host and port are required", path, i)
		}
		addr, err := netaddr.ParseIPPort(net.JoinHostPort(d.Host, d.Port))
		if err != nil {
			return nil, fmt.Errorf("invalid %s: databases[%d]: host must be an IP address: %w", path, i, err)
		}
		res = append(res, &dbTarget{cfg: d, addr: addr})
	}
	return res, nil
}

func (c *Container) listensOn(addr netaddr.IPPort) bool {
	c.lock.Lock()
	defer c.lock.Unlock()
	for la, byPid := range c.listens {
		if la.Port() != addr.Port() {
			continue
		}
		for pid, details := range byPid {
			if details == nil || !details.ClosedAt.IsZero() {
				continue
			}
			p := c.processes[pid]
			if p == nil || (addr.IP().IsLoopback() && !p.isHostNs()) {
				continue
			}
			switch {
			case la.IP() == addr.IP():
				return true
			case la.IP().IsUnspecified():
				if addr.IP().IsLoopback() {
					return true
				}
				for _, ip := range details.NsIPs {
					if ip == addr.IP() {
						return true
					}
				}
			}
		}
	}
	return false
}

func (r *Registry) resolveDatabaseTarget(t *dbTarget) *Container {
	for _, c := range r.containersById {
		if c.listensOn(t.addr) {
			return c
		}
	}
	return nil
}

func (r *Registry) reconcileDatabases() {
	for _, t := range r.databases {
		c := r.resolveDatabaseTarget(t)
		if c == nil {
			if t.exporter != nil { // the container is gone
				klog.Infof("database target %s: stopping exporter for %s", t, t.containerId)
				t.stop(r.reg)
			}
			if !t.missing {
				klog.Warningf("database target %s: no container listens on this address", t)
			}
			t.missing = true
			continue
		}
		t.missing = false
		if t.exporter != nil {
			if c.id == t.containerId {
				continue
			}
			klog.Infof("database target %s: stopping exporter for %s", t, t.containerId) // the address is now owned by another container
			t.stop(r.reg)
		}
		if err := t.start(r.reg, r.dbChanges, c.id); err != nil {
			klog.Warningf("database target %s: failed to start exporter: %s", t, err)
			continue
		}
		klog.Infof("database target %s: started exporter for %s", t, c.id)
	}
}

func (t *dbTarget) labels() prometheus.Labels {
	return prometheus.Labels{"container_id": string(t.containerId), "address": t.addr.String()}
}

func (t *dbTarget) start(reg prometheus.Registerer, changes dbtracker.ChangeEmitter, containerId ContainerID) error {
	scrapeInterval := *flags.ScrapeInterval
	collectTimeout := scrapeInterval - time.Second
	if collectTimeout < dbMinCollectTimeout {
		collectTimeout = dbMinCollectTimeout
	}
	e, err := exporter.New(
		exporter.Config{
			Type:        exporter.Type(t.cfg.Type),
			Addr:        t.addr.String(),
			Credentials: exporter.Credentials{Username: t.cfg.Credentials.Username, Password: t.cfg.Credentials.Password},
			Params:      t.cfg.Params,
		},
		exporter.Options{
			ScrapeInterval:   scrapeInterval,
			CollectTimeout:   collectTimeout,
			ChangeEmitter:    changes,
			MaxTablesPerDB:   dbMaxTablesPerDB,
			TrackSizes:       true,
			TrackBloat:       true,
			ExcludeDatabases: cacommon.DefaultExcludeDatabases,
		},
		logger.NewKlog(t.String()),
	)
	if err != nil {
		return err
	}
	t.containerId = containerId
	t.exporter = e
	if err = prometheus.WrapRegistererWith(t.labels(), reg).Register(t.exporter); err != nil {
		t.exporter.Close()
		t.exporter = nil
		return err
	}
	return nil
}

func (t *dbTarget) stop(reg prometheus.Registerer) {
	prometheus.WrapRegistererWith(t.labels(), reg).Unregister(t.exporter)
	t.exporter.Close()
	t.exporter = nil
	t.containerId = ""
}
