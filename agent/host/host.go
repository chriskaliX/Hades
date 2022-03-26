// collection of basic information about host
// @Reference: https://osquery.io/
package host

import (
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"go.uber.org/zap"
)

const (
	MAX_IP = 5
)

// atomic to make sure the value is sync
var (
	// string
	Hostname atomic.Value
	// []string{}
	PrivateIPv4 atomic.Value
	PublicIPv4  atomic.Value
	PrivateIPv6 atomic.Value
	PublicIPv6  atomic.Value
	// kernel & arch information
	Platform        string
	PlatformFamily  string
	PlatformVersion string
	KernelVersion   string
	Arch            string
	// Add cpu basic for display
	CpuNum string
	CpuMhz string
	// Add mem information
	Mem string
)

// Competely from Elkeid, but something with the IP need to be changed
// https://github.com/osquery/osquery/blob/d2be385d71f401c85872f00d479df8f499164c5a/osquery/tables/networking/posix/interfaces.cpp
func RefreshHost() {
	// hostname
	if hostname, err := os.Hostname(); err == nil {
		Hostname.Store(hostname)
	} else {
		zap.S().Error(err)
	}

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
					if (ip4[0] == 10) || (ip4[0] == 192 && ip4[1] == 168) || (ip4[0] == 172 && ip4[1]&0x10 == 0x10) {
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

	// truncate the private ip length
	if len(privateIPv4) > MAX_IP {
		privateIPv4 = privateIPv4[:MAX_IP]
	}
	if len(privateIPv6) > MAX_IP {
		privateIPv6 = privateIPv6[:MAX_IP]
	}

	PrivateIPv4.Store(privateIPv4)
	PublicIPv4.Store(publicIPv4)
	PrivateIPv6.Store(privateIPv6)
	PublicIPv6.Store(publicIPv6)
}

func init() {
	// init stable
	KernelVersion, _ = host.KernelVersion()
	Platform, PlatformFamily, PlatformVersion, _ = host.PlatformInformation()
	Arch, _ = host.KernelArch()
	// cpu related
	var mhz float64
	var cpuNum int
	cpuNum, _ = cpu.Counts(false)
	CpuNum = strconv.Itoa(cpuNum)
	if cpuInfo, err := cpu.Info(); err == nil {
		for _, c := range cpuInfo {
			mhz += c.Mhz
		}
		mhz /= float64(len(cpuInfo))
	}
	CpuMhz = strconv.FormatFloat(mhz/1000, 'f', 1, 64)
	RefreshHost()
}
