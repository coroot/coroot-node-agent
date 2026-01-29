package containers

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/coroot/coroot-node-agent/proc"

	"github.com/coreos/go-systemd/v22/dbus"
	gdbus "github.com/godbus/dbus/v5"

	"k8s.io/klog/v2"
)

var (
	dbusConn    *dbus.Conn
	dbusTimeout = time.Second

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

func init() {
	var err error
	dbusConn, err = dbus.NewConnection(func() (*gdbus.Conn, error) {
		c, err := gdbus.Dial("unix:path=" + proc.HostPath("/run/systemd/private"))
		if err != nil {
			return nil, err
		}
		methods := []gdbus.Auth{gdbus.AuthExternal(strconv.Itoa(os.Getuid()))}
		if err = c.Auth(methods); err != nil {
			dbusConn.Close()
			return nil, err
		}
		return c, nil
	})
	if err != nil {
		klog.Warningln("failed to connect to systemd bus:", err)
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

func getSystemdProperties(id string) SystemdProperties {
	props := SystemdProperties{}
	if dbusConn == nil {
		return props
	}
	ctx, cancel := context.WithTimeout(context.Background(), dbusTimeout)
	defer cancel()
	parts := strings.Split(id, "/")
	unit := parts[len(parts)-1]
	props.Unit = unit
	properties, err := dbusConn.GetAllPropertiesContext(ctx, unit)
	if err != nil {
		klog.Warningln("failed to get systemd properties:", err)
		return props
	}
	if v, ok := properties["TriggeredBy"]; ok {
		if values, _ := v.([]string); len(values) > 0 {
			props.TriggeredBy = values[0]
		}
	}
	if v, ok := properties["Type"]; ok {
		props.Type, _ = v.(string)
	}
	return props
}
