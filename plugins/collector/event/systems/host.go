// Host is for collecting host from local network.
// AND DO REMEMBER THAT THIS MAY CAUSE THE eBPFdriver plugin report all
// METHODS: ARP / PING etc. VERY SLOW
// THIS SHOULD BE CONTROLLED BY THE SERVER
package systems

import (
	"collector/eventmanager"
	"collector/utils"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/go-ping/ping"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
)

type HostScanner struct {
	Addrs []string `json:"addrs"`
}

func (HostScanner) DataType() int { return 3007 }

func (HostScanner) Flag() eventmanager.EventMode { return eventmanager.Trigger }

func (HostScanner) Name() string { return "host_scanner" }

func (HostScanner) Immediately() bool { return false }

func (h *HostScanner) Run(s SDK.ISandbox, sig chan struct{}) (err error) {
	hash := utils.Hash()
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
		// every scanner, only /24 is supported, so randomly 512
		if len(availableAddrs) > 512 {
			rand.Shuffle(len(availableAddrs), func(i, j int) { availableAddrs[i], availableAddrs[j] = availableAddrs[j], availableAddrs[i] })
		}
	scan:
		for _, addr := range availableAddrs {
			select {
			case <-sig:
				break scan
			default:
				pinger, err := ping.NewPinger(addr)
				if err != nil {
					continue
				}
				pinger.Count = 2
				pinger.Timeout = time.Duration(3 * time.Second)
				pinger.SetPrivileged(false)
				pinger.Run()
				if pinger.Statistics().PacketsRecv > 0 {
					rec := &protocol.Record{
						DataType:  int32(h.DataType()),
						Timestamp: time.Now().Unix(),
						Data: &protocol.Payload{
							Fields: map[string]string{
								"addr":        addr,
								"package_seq": hash,
							},
						},
					}
					s.SendRecord(rec)
				}
				time.Sleep(400 * time.Millisecond)
			}
		}
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

// THIS SHOULD NEVER RUN
func init() { addEvent(&HostScanner{}, 24*time.Hour) }
