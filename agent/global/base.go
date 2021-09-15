package global

// 信息初始化
import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

var (
	PrivateIPv4     []string
	PrivateIPv6     []string
	AgentID         string
	Hostname        string
	Platform        string
	PlatformFamily  string
	PlatformVersion string
	KernelVersion   string
	Time            uint
)

const (
	Version = "0.0.1"
)

func Getinterface() error {
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't get interfaces:%v", err)
		return err
	}
	for _, i := range interfaces {
		// 过滤掉 docker 信息
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
				if strings.HasPrefix(ip.String(), "fd") {
					PrivateIPv6 = append(PrivateIPv6, ip.String())
				}
			} else {
				// 保留地址过滤
				if strings.HasPrefix(ip.String(), "169.254.") {
					continue
				}
				if strings.HasPrefix(ip.String(), "10.") || strings.HasPrefix(ip.String(), "192.168.") || regexp.MustCompile(`^172\.([1][6-9]|[2]\d|[3][0-1])\.`).MatchString(ip.String()) {
					PrivateIPv4 = append(PrivateIPv4, ip.String())
				}
			}
		}
	}
	return nil
}

func Getuuid() error {
	id, err := ioutil.ReadFile("agent-id")
	if err != nil {
		AgentID = uuid.New().String()
		err = ioutil.WriteFile("agent-id", []byte(AgentID), 0700)
		if err != nil {
			AgentID = "AGENT-ID-ERROR-" + err.Error()
			fmt.Fprintf(os.Stderr, "failed to write agent id file:%v", err)
			return err
		}
	} else {
		_, err = uuid.Parse(string(id))
		if err != nil {
			AgentID = uuid.New().String()
			err = ioutil.WriteFile("agent-id", []byte(AgentID), 0700)
			if err != nil {
				AgentID = "AGENT-ID-ERROR-" + err.Error()
				fmt.Fprintf(os.Stderr, "failed to write agent id file:%v", err)
				return err
			}
		} else {
			AgentID = string(id)
			return nil
		}
	}
	return nil
}
