// Host is for collecting host from local network.
// AND DO REMEMBER THAT THIS MAY CAUSE THE eBPFdriver plugin report all
// METHODS: ARP / PING etc. VERY SLOW
// THIS SHOULD BE CONTROLLED BY THE SERVER
package event

import (
	"collector/eventmanager"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	"github.com/go-ping/ping"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
)

type HostScanner struct {
	Addrs []string `json:"addrs"`
}

func (HostScanner) DataType() int { return 3007 }

func (n *HostScanner) Flag() int { return eventmanager.Trigger }

func (HostScanner) Name() string { return "host_scanner" }

func (HostScanner) Immediately() bool { return false }

func (h *HostScanner) Run(s SDK.ISandbox, sig chan struct{}) (err error) {
	h.Addrs = h.Addrs[:0]
	var availableAddrs []string
	interfaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, inf := range interfaces {
		// skip loopback
		if inf.Flags&net.FlagLoopback != 0 {
			continue
		}
		// the net is down
		if inf.Flags&net.FlagUp == 0 {
			continue
		}
		if strings.HasPrefix(inf.Name, "docker") {
			continue
		}
		// get the available addrs
		addrs, err := inf.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip, ipnet, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			// skip if it is not internal network
			if !ip.IsPrivate() {
				continue
			}
			// go through the ipnet
			for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); h.iter(ip) {
				availableAddrs = append(availableAddrs, ip.String())
			}
		}
		// scan the network with ping (or ARP? configurable)
		// every scanner, only /24 is supported, so randomly 256
		if len(availableAddrs) > 256 {
			rand.Shuffle(len(availableAddrs), func(i, j int) { availableAddrs[i], availableAddrs[j] = availableAddrs[j], availableAddrs[i] })
		}
		for _, addr := range availableAddrs {
			pinger, err := ping.NewPinger(addr)
			if err != nil {
				continue
			}
			pinger.Count = 2
			pinger.Timeout = time.Duration(3 * time.Second)
			pinger.SetPrivileged(false)
			pinger.Run()
			if pinger.Statistics().PacketsRecv > 0 {
				h.Addrs = append(h.Addrs, addr)
			}
			time.Sleep(400 * time.Millisecond)
		}
		data, err := sonic.MarshalString(h.Addrs)
		if err != nil {
			return err
		}
		return s.SendRecord(&protocol.Record{
			DataType:  int32(h.DataType()),
			Timestamp: time.Now().Unix(),
			Data: &protocol.Payload{
				Fields: map[string]string{
					"data": data,
				},
			},
		})
	}
	return
}

func (h HostScanner) iter(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
