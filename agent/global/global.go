package global

import (
	"agent/global/structs"
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
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
)

var (
	// 全局上下文
	Context context.Context

	// 上传数据管道
	UploadChannel chan map[string]string

	// 进程管道
	ProcessChannel chan structs.Process

	// pid 管道
	PidChannel chan uint32

	// GrpcChannel 全局上传管道
	GrpcChannel chan []*Record
)

const (
	Version = "0.0.0.1"
)

func globalTime() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			Time = int(time.Now().Unix())
		case <-Context.Done():
			return
		}
	}
}

func init() {
	Context = context.Context(context.Background())
	// 全局时间
	go globalTime()
	// 初始化全局的上传管道
	UploadChannel = make(chan map[string]string, 100)
	ProcessChannel = make(chan structs.Process, 1000)
	PidChannel = make(chan uint32, 100)

	// 初始信息
	Hostname, _ = os.Hostname()
	KernelVersion, _ = host.KernelVersion()
	Platform, PlatformFamily, PlatformVersion, _ = host.PlatformInformation()
	// 写入文件形式保存
	Getuuid()
	Getinterface()
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

func Getinterface() error {
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't get interfaces:%v", err)
		return err
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
	return nil
}
