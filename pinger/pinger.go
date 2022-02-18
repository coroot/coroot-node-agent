package pinger

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/coroot/coroot-node-agent/proc"
	"github.com/vishvananda/netns"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"inet.af/netaddr"
	"k8s.io/klog/v2"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

const (
	pingReplyPollTimeout         = 10 * time.Millisecond
	protocolICMP                 = 1 // Internet Control Message
	SOF_TIMESTAMPING_TX_SOFTWARE = 1 << 1
	SOF_TIMESTAMPING_TX_SCHED    = 1 << 8
	SOF_TIMESTAMPING_RX_SOFTWARE = 1 << 3
)

var (
	pingerID = os.Getpid() & 0xFFFF
)

type sentPacket struct {
	seq         int
	txTimestamp time.Time
}

func Ping(ns netns.NsHandle, originNs netns.NsHandle, targets []netaddr.IP, timeout time.Duration) (map[netaddr.IP]float64, error) {
	if len(targets) < 1 {
		return nil, nil
	}
	var conn *net.IPConn
	err := proc.ExecuteInNetNs(ns, originNs, func() error {
		c, err := openConn()
		if err != nil {
			return err
		}
		conn = c
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open IPConn: %s", err)
	}
	defer conn.Close()
	f, err := conn.File()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fd := int(f.Fd())

	ids := make(map[netaddr.IP]*sentPacket, len(targets))
	for seq, ip := range targets {
		pkt := &sentPacket{seq: seq + 1, txTimestamp: time.Now()}
		if err := send(conn, pkt.seq, ip.IPAddr()); err != nil {
			if strings.HasPrefix(err.Error(), "resource temporarily unavailable") {
				continue
			}
			return nil, fmt.Errorf("failed to send packet to %s: %s", ip, err)
		}
		if pkt.txTimestamp, err = getTxTimestamp(fd); err != nil {
			if strings.HasPrefix(err.Error(), "resource temporarily unavailable") {
				continue
			}
			return nil, fmt.Errorf("failed to get RX timestamp: %s", err)
		}
		ids[ip] = pkt
	}

	timeoutTicker := time.NewTimer(timeout)
	defer timeoutTicker.Stop()

	rttByIp := make(map[netaddr.IP]float64, len(targets))
	for {
		select {
		case <-timeoutTicker.C:
			return rttByIp, nil
		default:
			if len(rttByIp) == len(targets) {
				return rttByIp, nil
			}
			remoteAddr, echoReply, rxTimestamp, err := receive(conn)
			if err != nil {
				if !strings.Contains(err.Error(), "interrupted system call") { // recvmsg timeout is not an issue
					klog.Errorln(err)
				}
				continue
			}
			if echoReply == nil {
				continue
			}
			if echoReply.ID != pingerID {
				continue
			}
			ip, ok := netaddr.FromStdIP(remoteAddr.IP)
			if !ok {
				continue
			}
			if pkt, ok := ids[ip]; ok && pkt.seq == echoReply.Seq {
				rtt := rxTimestamp.Sub(pkt.txTimestamp).Seconds()
				if rtt < 0 { // a small negative value is possible if the clock has adjusted by ntpd
					rtt = 0
				}
				rttByIp[ip] = rtt
			}
		}
	}
}

func send(conn *net.IPConn, seq int, ip net.Addr) error {
	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{
			ID:  pingerID,
			Seq: seq,
		},
	}
	data, err := msg.Marshal(nil)
	if err != nil {
		return err
	}
	_, err = conn.WriteTo(data, ip)
	return err
}

func getTimestampFromOutOfBandData(oob []byte, oobn int) (time.Time, error) {
	var t time.Time
	cms, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return t, err
	}
	for _, cm := range cms {
		if cm.Header.Level == syscall.SOL_SOCKET && cm.Header.Type == syscall.SO_TIMESTAMP {
			var tv syscall.Timeval
			if err := binary.Read(bytes.NewBuffer(cm.Data), binary.LittleEndian, &tv); err != nil {
				return t, err
			}
			return time.Unix(tv.Unix()), nil
		}
	}
	return t, errors.New("no timestamp found")
}

func getTxTimestamp(socketFd int) (time.Time, error) {
	pktBuf := make([]byte, 1024)
	oob := make([]byte, 1024)
	var t time.Time
	_, oobn, _, _, err := syscall.Recvmsg(socketFd, pktBuf, oob, syscall.MSG_ERRQUEUE)
	if err != nil {
		return t, err
	}
	return getTimestampFromOutOfBandData(oob, oobn)
}

func receive(conn *net.IPConn) (*net.IPAddr, *icmp.Echo, time.Time, error) {
	pktBuf := make([]byte, 1024)
	oob := make([]byte, 1024)
	var ts time.Time

	_ = conn.SetReadDeadline(time.Now().Add(pingReplyPollTimeout))
	n, oobn, _, ra, err := conn.ReadMsgIP(pktBuf, oob)
	if err != nil {
		if neterr, ok := err.(*net.OpError); ok && neterr.Timeout() {
			return nil, nil, ts, nil
		}
		if strings.Contains(err.Error(), "no message of desired type") {
			return nil, nil, ts, nil
		}
		return nil, nil, ts, err
	}

	if ts, err = getTimestampFromOutOfBandData(oob, oobn); err != nil {
		return nil, nil, ts, fmt.Errorf("failed to get RX timestamp: %s", err)
	}

	echo, err := extractEchoFromPacket(pktBuf, n)
	if err != nil {
		return nil, nil, ts, fmt.Errorf("failed to extract ICMP Echo from IPv4 packet %s: %s", ra, err)
	}
	return ra, echo, ts, nil
}

func extractEchoFromPacket(pktBuf []byte, n int) (*icmp.Echo, error) {
	if n < ipv4.HeaderLen {
		return nil, errors.New("malformed IPv4 packet")
	}
	pktBuf = pktBuf[ipv4.HeaderLen:]
	var m *icmp.Message
	m, err := icmp.ParseMessage(protocolICMP, pktBuf)
	if err != nil {
		return nil, err
	}
	if m.Type != ipv4.ICMPTypeEchoReply {
		return nil, nil
	}
	echo, ok := m.Body.(*icmp.Echo)
	if !ok {
		return nil, fmt.Errorf("malformed ICMP message body: %T", m.Body)
	}
	return echo, nil
}

func openConn() (*net.IPConn, error) {
	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	ipconn := conn.(*net.IPConn)
	f, err := ipconn.File()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fd := int(f.Fd())

	flags := SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_TX_SCHED | SOF_TIMESTAMPING_RX_SOFTWARE
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPING, flags); err != nil {
		return nil, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMP, 1); err != nil {
		return nil, err
	}
	timeout := syscall.Timeval{Sec: 0, Usec: 1000}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &timeout); err != nil {
		return nil, err
	}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &timeout); err != nil {
		return nil, err
	}
	return ipconn, nil
}
