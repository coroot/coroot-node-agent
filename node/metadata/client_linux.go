//go:build linux

package metadata

import (
	"context"
	"net"
	"net/http"

	"github.com/coroot/coroot-node-agent/proc"
	"k8s.io/klog/v2"
)

func newMetadataClient() (*http.Client, func()) {
	hostNetNs, err := proc.GetHostNetNs()
	if err != nil {
		klog.Errorln("failed to get host netns:", err)
		return &http.Client{Timeout: metadataServiceTimeout}, func() {}
	}
	agentNetNs, err := proc.GetSelfNetNs()
	if err != nil {
		hostNetNs.Close()
		klog.Errorln("failed to get self netns:", err)
		return &http.Client{Timeout: metadataServiceTimeout}, func() {}
	}
	c := &http.Client{
		Timeout: metadataServiceTimeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, addr string) (conn net.Conn, err error) {
				err = proc.ExecuteInNetNs(hostNetNs, agentNetNs, func() error {
					conn, err = net.DialTimeout(network, addr, metadataServiceTimeout)
					return err
				})
				return conn, err
			},
		},
	}
	return c, func() {
		hostNetNs.Close()
		agentNetNs.Close()
	}
}
