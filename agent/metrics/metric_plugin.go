package metrics

import (
	"agent/plugin"
	"agent/proto"
	"agent/transport"
	"runtime"
	"strconv"
	"time"

	"github.com/chriskaliX/SDK/config"
	"github.com/mitchellh/mapstructure"
	"go.uber.org/zap"
)

func init() {
	addMetric(&PluginMetric{})
}

type PluginMetric struct {
	PName      string `mapstructure:"name"`
	PVersion   string `mapstructure:"pversion"`
	Pid        string `mapstructure:"pid"`
	Cpu        string `mapstructure:"cpu"`
	Rss        string `mapstructure:"rss"`
	ReadSpeed  string `mapstructure:"read_speed"`
	WriteSpeed string `mapstructure:"write_speed"`
	FdCnt      string `mapstructure:"fd_cnt"`
	StartAt    string `mapstructure:"start_at"`
	TxTps      string `mapstructure:"tx_tps"`
	RxTps      string `mapstructure:"rx_tps"`
	TxSpeed    string `mapstructure:"tx_speed"`
	RxSpeed    string `mapstructure:"rx_speed"`
	Du         string `mapstructure:"du"`
	Grs        string `mapstructure:"grs"`
}

func (m *PluginMetric) Name() string {
	return "plugin"
}

func (h *PluginMetric) Init() bool {
	return false
}

func (m *PluginMetric) Flush(now time.Time) {
	plgs := plugin.DefaultManager.GetAll()
	for _, plg := range plgs {
		if plg.IsExited() {
			continue
		}
		m.PName = plg.Name()
		m.PVersion = plg.Version()
		if cpu, rss, rs, ws, fdCnt, startAt, err := getProcResource(plg.Pid()); err == nil {
			m.Cpu = strconv.FormatFloat(cpu, 'f', 8, 64)
			m.ReadSpeed = strconv.FormatFloat(rs, 'f', 8, 64)
			m.WriteSpeed = strconv.FormatFloat(ws, 'f', 8, 64)
			m.Rss = strconv.FormatUint(rss, 10)
			m.FdCnt = strconv.FormatInt(int64(fdCnt), 10)
			m.StartAt = strconv.FormatInt(startAt, 10)
		} else {
			zap.S().Error(err)
		}

		m.Du = strconv.FormatUint(getDirSize(plg.GetWorkingDirectory(), ""), 10)
		RxSpeed, TxSpeed, RxTPS, TxTPS := plg.GetState()
		m.RxTps = strconv.FormatFloat(RxTPS, 'f', 8, 64)
		m.TxTps = strconv.FormatFloat(TxTPS, 'f', 8, 64)
		m.RxSpeed = strconv.FormatFloat(RxSpeed, 'f', 8, 64)
		m.TxSpeed = strconv.FormatFloat(TxSpeed, 'f', 8, 64)
		m.Grs = strconv.Itoa(runtime.NumGoroutine())

		fields := make(map[string]string, 20)
		if err := mapstructure.Decode(m, fields); err == nil {
			rec := &proto.Record{
				DataType:  config.DTPluginStatus,
				Timestamp: now.Unix(),
				Data: &proto.Payload{
					Fields: fields,
				},
			}
			transport.DefaultTrans.Transmission(rec, false)
		}
	}
}
