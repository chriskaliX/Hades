package systems

import (
	"collector/eventmanager"
	"collector/utils"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
)

type NetInterface struct{}

func (NetInterface) DataType() int { return 3012 }

func (NetInterface) Name() string { return "net_interface" }

func (NetInterface) Flag() eventmanager.EventMode { return eventmanager.Periodic }

func (NetInterface) Immediately() bool { return false }

// TODO: IO counter?
func (n NetInterface) Run(s SDK.ISandbox, sig chan struct{}) (err error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return
	}
	hash := utils.Hash()
	for _, nif := range interfaces {
		if addrs, err := nif.Addrs(); err == nil {
			var addrList []string
			for _, addr := range addrs {
				addrList = append(addrList, addr.String())
			}
			s.SendRecord(&protocol.Record{
				DataType:  int32(n.DataType()),
				Timestamp: time.Now().Unix(),
				Data: &protocol.Payload{
					Fields: map[string]string{
						"name":          nif.Name,
						"flags":         nif.Flags.String(),
						"hardware_addr": nif.HardwareAddr.String(),
						"addrs":         strings.Join(addrList, ","),
						"index":         strconv.Itoa(nif.Index),
						"mtu":           strconv.Itoa(nif.MTU),
						"package_seq":   hash,
					},
				},
			})
		}
	}
	return
}

func init() { addEvent(&NetInterface{}, 24*time.Hour) }
