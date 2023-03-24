package agent

import "sync/atomic"

var (
	Hostname    atomic.Value
	PrivateIPv4 atomic.Value
	PublicIPv4  atomic.Value
	PrivateIPv6 atomic.Value
	PublicIPv6  atomic.Value
)
