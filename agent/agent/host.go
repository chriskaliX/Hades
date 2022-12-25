package agent

import "sync/atomic"

// Host related information
var (
	Hostname    atomic.Value
	PrivateIPv4 atomic.Value
	PublicIPv4  atomic.Value
	PrivateIPv6 atomic.Value
	PublicIPv6  atomic.Value
)
