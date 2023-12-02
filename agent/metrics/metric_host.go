package metrics

import (
	"github.com/chriskaliX/Hades/agent/agent"
	"net"
	"os"
	"strings"
	"time"
)

const max = 5

type HostMetric struct{}

func (h *HostMetric) Name() string {
	return "host"
}

func (h *HostMetric) Init() bool {
	return true
}

func (h *HostMetric) Flush(time.Time) {
	// hostname
	hostname, _ := os.Hostname()
	agent.Hostname.Store(hostname)
	// ip list
	privateIPv4 := []string{}
	privateIPv6 := []string{}
	publicIPv4 := []string{}
	publicIPv6 := []string{}
	if interfaces, err := net.Interfaces(); err == nil {
		for _, i := range interfaces {
			// skip docker
			if strings.HasPrefix(i.Name, "docker") || strings.HasPrefix(i.Name, "lo") {
				continue
			}
			addrs, err := i.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				ip, _, err := net.ParseCIDR(addr.String())
				if err != nil || !ip.IsGlobalUnicast() {
					continue
				}
				if ip4 := ip.To4(); ip4 != nil {
					if (ip4[0] == 10) ||
						(ip4[0] == 192 && ip4[1] == 168) ||
						(ip4[0] == 172 && (ip4[1] >= 16 || ip4[1] < 32)) {
						privateIPv4 = append(privateIPv4, ip4.String())
					} else {
						publicIPv4 = append(publicIPv4, ip4.String())
					}
				} else if len(ip) == net.IPv6len {
					if ip[0] == 0xfd {
						privateIPv6 = append(privateIPv6, ip.String())
					} else {
						publicIPv6 = append(publicIPv6, ip.String())
					}
				}
			}
		}
	}
	if len(privateIPv4) > max {
		privateIPv4 = privateIPv4[:max]
	}
	if len(privateIPv6) > max {
		privateIPv6 = privateIPv6[:max]
	}
	agent.PrivateIPv4.Store(privateIPv4)
	agent.PublicIPv4.Store(publicIPv4)
	agent.PrivateIPv6.Store(privateIPv6)
	agent.PublicIPv6.Store(publicIPv6)
}

func init() {
	addMetric(&HostMetric{})
}
