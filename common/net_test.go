package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"inet.af/netaddr"
)

func TestConnectionFilter(t *testing.T) {
	f := connectionFilter{whitelist: map[string]netaddr.IPPrefix{}}
	assert.False(t, f.ShouldBeSkipped(netaddr.MustParseIP("127.0.0.1"), netaddr.MustParseIP("127.0.0.1")))
	assert.False(t, f.ShouldBeSkipped(netaddr.MustParseIP("192.168.1.1"), netaddr.MustParseIP("127.0.0.1")))

	assert.True(t, f.ShouldBeSkipped(netaddr.MustParseIP("1.1.1.1"), netaddr.MustParseIP("2.2.2.2")))
	assert.False(t, f.ShouldBeSkipped(netaddr.MustParseIP("1.1.1.1"), netaddr.MustParseIP("192.168.1.1")))
	// because the actual dest is allowed, the dest is added to whitelist
	assert.False(t, f.ShouldBeSkipped(netaddr.MustParseIP("1.1.1.1"), netaddr.MustParseIP("2.2.2.2")))

	assert.True(t, f.ShouldBeSkipped(netaddr.MustParseIP("2.2.2.2"), netaddr.MustParseIP("2.2.2.2")))
	f.WhitelistPrefix(netaddr.MustParseIPPrefix("2.2.2.0/24"))
	assert.False(t, f.ShouldBeSkipped(netaddr.MustParseIP("2.2.2.2"), netaddr.MustParseIP("2.2.2.2")))

	assert.True(t, f.ShouldBeSkipped(netaddr.MustParseIP("3.3.3.3"), netaddr.MustParseIP("3.3.3.3")))
	f.WhitelistPrefix(netaddr.MustParseIPPrefix("4.4.4.4/32"))
	assert.False(t, f.ShouldBeSkipped(netaddr.MustParseIP("3.3.3.3"), netaddr.MustParseIP("4.4.4.4")))
}

func TestDestinationKey(t *testing.T) {
	d := netaddr.IPPortFrom(netaddr.MustParseIP("10.10.10.10"), 443)
	ad := netaddr.IPPortFrom(netaddr.MustParseIP("127.0.0.1"), 443)

	assert.Equal(t, "10.10.10.10:443 (127.0.0.1:443)", NewDestinationKey(d, ad, "").String())

	assert.Equal(t,
		"aa.bb.s3.amazonaws.com:443 ()",
		NewDestinationKey(d, ad, "aa.bb.s3.amazonaws.com").String(),
	)

	assert.Equal(t,
		"amazonlinux-2-repos-us-east-1.s3.dualstack.us-east-1.amazonaws.com:443 ()",
		NewDestinationKey(d, ad, "amazonlinux-2-repos-us-east-1.s3.dualstack.us-east-1.amazonaws.com").String(),
	)

	assert.Equal(t,
		"bucket.s3.amazonaws.com:443 ()",
		NewDestinationKey(d, ad, "bucket.s3.amazonaws.com").String(),
	)

	assert.Equal(t,
		"bucket.s3-accelerate.amazonaws.com:443 ()",
		NewDestinationKey(d, ad, "bucket.s3-accelerate.amazonaws.com").String(),
	)

	assert.Equal(t,
		"bucket.s3.amazonaws.com.default.svc.cluster.local:443 ()",
		NewDestinationKey(d, ad, "bucket.s3.amazonaws.com.default.svc.cluster.local").String(),
	)
}
