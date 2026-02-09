package containers

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/coroot/coroot-node-agent/proc"

	"github.com/coreos/go-systemd/v22/dbus"
	gdbus "github.com/godbus/dbus/v5"
)

var (
	dbusTimeout = time.Second
	dbusClient  = NewDbusClient()

	systemServicePrefixes = []string{
		"systemd-",
		"dbus",
		"getty",
		"system-serial",
		"system-getty",
		"serial-getty",
		"snapd",
		"packagekit",
		"unattended-upgrades",
		"multipathd",
		"qemu-guest-agent",
		"irqbalance",
		"networkd-dispatcher",
		"rpcbind",
	}
)

type DbusClient struct {
	conn  *dbus.Conn
	cache map[string]map[string]any
}

func NewDbusClient() *DbusClient {
	return &DbusClient{
		cache: map[string]map[string]any{},
	}
}

func (c *DbusClient) close() {
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

func (c *DbusClient) connect() error {
	var err error
	c.conn, err = dbus.NewConnection(func() (*gdbus.Conn, error) {
		conn, err := gdbus.Dial("unix:path=" + proc.HostPath("/run/systemd/private"))
		if err != nil {
			return nil, err
		}
		methods := []gdbus.Auth{gdbus.AuthExternal(strconv.Itoa(os.Getuid()))}
		if err = conn.Auth(methods); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	})
	if err != nil {
		return fmt.Errorf("failed to connect to systemd bus: %w", err)
	}
	return nil
}

func (c *DbusClient) GetAllPropertiesContext(ctx context.Context, unit string, retry bool) (map[string]any, error) {
	if res, ok := c.cache[unit]; ok {
		return res, nil
	}
	if c.conn == nil {
		if err := c.connect(); err != nil {
			return nil, err
		}
	}
	res, err := c.conn.GetAllPropertiesContext(ctx, unit)
	switch {
	case err == nil:
		c.cache[unit] = res
		return res, nil
	case retry:
		c.close()
		return c.GetAllPropertiesContext(ctx, unit, false)
	default:
		return nil, err
	}
}

type SystemdProperties struct {
	Unit        string
	TriggeredBy string
	Type        string
}

func (sp SystemdProperties) IsEmpty() bool {
	return sp.TriggeredBy == "" && sp.Type == ""
}

func (sp SystemdProperties) IsSystemService() bool {
	switch sp.Type {
	case "oneshot", "dbus":
		return true
	}
	if strings.HasSuffix(sp.TriggeredBy, ".timer") {
		return true
	}
	for _, prefix := range systemServicePrefixes {
		if strings.HasPrefix(sp.Unit, prefix) {
			return true
		}
	}
	return false
}

func getSystemdProperties(id string) (SystemdProperties, error) {
	props := SystemdProperties{}
	ctx, cancel := context.WithTimeout(context.Background(), dbusTimeout)
	defer cancel()
	parts := strings.Split(id, "/")
	for _, p := range parts {
		if strings.HasSuffix(p, ".service") {
			props.Unit = p
			break
		}
	}
	if props.Unit == "" {
		props.Unit = parts[len(parts)-1]
	}
	properties, err := dbusClient.GetAllPropertiesContext(ctx, props.Unit, true)
	if err != nil {
		return props, fmt.Errorf("failed to get systemd properties: %w", err)
	}
	if v, ok := properties["TriggeredBy"]; ok {
		if values, _ := v.([]string); len(values) > 0 {
			props.TriggeredBy = values[0]
		}
	}
	if v, ok := properties["Type"]; ok {
		props.Type, _ = v.(string)
	}
	return props, nil
}
