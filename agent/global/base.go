package global

// 信息初始化
import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"

	"github.com/google/uuid"
)

// 字节这里改用了 atomic.Value 看一下为啥
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
	// hostname 获取
	Hostname, _ = os.Hostname()
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
		for _, addr := range addr {
			// 解析 ip 地址
			ip, _, err := net.ParseCIDR(addr.String())
			// 增加了一个过滤
			if err != nil || !ip.IsGlobalUnicast() {
				continue
			}

			if ip4 := ip.To4(); ip4 != nil {
				// 具体看下,位运算比较快
				if (ip4[0] == 10) || (ip4[0] == 192 && ip4[1] == 168) || (ip4[0] == 172 && ip4[1]&0x10 == 0x10) {
					PrivateIPv4 = append(PrivateIPv4, ip4.String())
				}
			} else if len(ip) == net.IPv6len {
				if ip[0] == 0xfd {
					PrivateIPv6 = append(PrivateIPv6, ip.String())
				}
			}
		}
	}

	// 新增 IP 阻隔, 防止过大. 这里都参考字节 Elkeid v1.7-rc
	if len(PrivateIPv4) > 5 {
		PrivateIPv4 = PrivateIPv4[:5]
	}
	if len(PrivateIPv6) > 5 {
		PrivateIPv6 = PrivateIPv6[:5]
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
