package networks

import (
	"collector/eventmanager"
	"collector/utils"
	"strings"
	"time"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/coreos/go-iptables/iptables"
)

const (
	tableFilter  = "filter"
	tableNat     = "nat"
	tableRaw     = "raw"
	tableMangble = "mangle"
)

var tableList = []string{tableFilter, tableNat, tableNat, tableMangble}
var iptablesInterval = 50 * time.Millisecond

// The iptables in OSQUERY does not work well since it only reads /proc/net/ip_tables_names
// and not works if new nftables is introduced.
type Iptables struct{}

func (Iptables) DataType() int { return 3013 }

func (Iptables) Name() string { return "iptables" }

func (Iptables) Flag() eventmanager.EventMode { return eventmanager.Periodic }

func (Iptables) Immediately() bool { return false }

func (i Iptables) Run(s SDK.ISandbox, sig chan struct{}) (err error) {
	hash := utils.Hash()
	for _, name := range tableList {
		if records, err := i.listTable(name); err == nil {
			for _, record := range records {
				rec := &protocol.Record{
					DataType:  int32(i.DataType()),
					Timestamp: utils.Clock.Now().Unix(),
					Data: &protocol.Payload{
						Fields: record,
					},
				}
				rec.Data.Fields["package_seq"] = hash
				s.SendRecord(rec)
			}
		}
	}
	return
}

func (Iptables) listTable(name string) (m []map[string]string, err error) {
	tables, err := iptables.New()
	if err != nil {
		return nil, err
	}
	chains, err := tables.ListChains(name)
	if err != nil {
		return nil, err
	}

	for _, chain := range chains {
		time.Sleep(iptablesInterval)
		rule, err := tables.List(name, chain)
		if err != nil {
			continue
		}
		stats, err := tables.Stats(name, chain)
		if err != nil {
			continue
		}

		if len(stats) > 0 {
			for _, stat := range stats {
				if len(stat) < 10 {
					continue
				}
				ipt := map[string]string{
					"table":       name,
					"chain":       chain,
					"rule":        strings.Join(rule, " "),
					"pkt":         stat[0],
					"bytes":       stat[1],
					"target":      stat[2],
					"prot":        stat[3],
					"opt":         stat[4],
					"in":          stat[5],
					"out":         stat[6],
					"source":      stat[7],
					"destination": stat[8],
					"options":     stat[9],
				}
				m = append(m, ipt)
			}
		} else {
			m = append(m, map[string]string{
				"table":       name,
				"chain":       chain,
				"rule":        strings.Join(rule, " "),
				"pkt":         "",
				"bytes":       "",
				"target":      "",
				"prot":        "",
				"opt":         "",
				"in":          "",
				"out":         "",
				"source":      "",
				"destination": "",
				"options":     "",
			})
		}
	}
	return
}

func init() { addEvent(&Iptables{}, 24*time.Hour) }
