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
	conn        *dbus.Conn
	dbusTimeout = time.Second
)

func init() {
	var err error
	conn, err = dbus.NewConnection(func() (*gdbus.Conn, error) {
		c, err := gdbus.Dial("unix:path=" + proc.HostPath("/run/systemd/private"))
		if err != nil {
			return nil, err
		}
		methods := []gdbus.Auth{gdbus.AuthExternal(strconv.Itoa(os.Getuid()))}
		if err = c.Auth(methods); err != nil {
			conn.Close()
			return nil, err
		}
		return c, nil
	})
	if err != nil {
		klog.Warningln("failed to connect to systemd bus:", err)
	}
}

func SystemdTriggeredBy(id string) string {
	if conn == nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), dbusTimeout)
	defer cancel()
	parts := strings.Split(id, "/")
	unit := parts[len(parts)-1]
	if prop, _ := conn.GetUnitPropertyContext(ctx, unit, "TriggeredBy"); prop != nil {
		if values, _ := prop.Value.Value().([]string); len(values) > 0 {
			return values[0]
		}
	}
	return ""
}
