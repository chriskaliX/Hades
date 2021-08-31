package global

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/host"
)

var (
	Time            int
	Hostname        string
	Platform        string
	PlatformVersion string
	PrivateIPv4     []string
	KernelVersion   string
	PlatformFamily  string
	AgentID         string
	UploadChannel   chan map[string]string
)

const (
	Version = "0.0.0.1"
)

func globalTime() {
	for {
		Time = int(time.Now().Unix())
		time.Sleep(time.Duration(time.Second))
	}
}

func init() {
	// 全局时间
	go globalTime()
	// 初始化全局的上传管道
	UploadChannel = make(chan map[string]string, 100)

	// 初始信息
	Hostname, _ = os.Hostname()
	KernelVersion, _ = host.KernelVersion()
	Platform, PlatformFamily, PlatformVersion, _ = host.PlatformInformation()

	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cann't get interfaces:%v", err)
	}
	for _, i := range interfaces {
		if strings.HasPrefix(i.Name, "docker") || strings.HasPrefix(i.Name, "lo") {
			continue
		}
		addr, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, j := range addr {
			ip, _, err := net.ParseCIDR(j.String())
			if err != nil {
				continue
			}
			if ip.To4() == nil {
				if strings.HasPrefix(ip.String(), "fe80") {
					continue
				}
			} else {
				if strings.HasPrefix(ip.String(), "169.254.") {
					continue
				}
				if strings.HasPrefix(ip.String(), "10.") || strings.HasPrefix(ip.String(), "192.168.") || regexp.MustCompile(`^172\.([1][6-9]|[2]\d|[3][0-1])\.`).MatchString(ip.String()) {
					PrivateIPv4 = append(PrivateIPv4, ip.String())
				}

			}
		}
	}
}
