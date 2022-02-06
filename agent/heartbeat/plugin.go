package heartbeat

import (
	"agent/core"
	"agent/plugin"
	"agent/proto"
	"agent/resource"
	"os"
	"strconv"
	"time"

	"go.uber.org/zap"
)

func getPlgStat(now time.Time) {
	plgs := plugin.DefaultManager.GetAll()
	for _, plg := range plgs {
		if !plg.IsExited() {
			rec := &proto.Record{
				DataType:  1001,
				Timestamp: now.Unix(),
				Data: &proto.Payload{
					Fields: map[string]string{"name": plg.Name(), "pversion": plg.Version()},
				},
			}
			cpuPercent, rss, readSpeed, writeSpeed, fds, startAt, err := resource.GetProcResouce(plg.Pid())
			if err != nil {
				zap.S().Error(err)
			} else {
				rec.Data.Fields["cpu"] = strconv.FormatFloat(cpuPercent, 'f', 8, 64)
				rec.Data.Fields["rss"] = strconv.FormatUint(rss, 10)
				rec.Data.Fields["read_speed"] = strconv.FormatFloat(readSpeed, 'f', 8, 64)
				rec.Data.Fields["write_speed"] = strconv.FormatFloat(writeSpeed, 'f', 8, 64)
				rec.Data.Fields["pid"] = strconv.Itoa(os.Getpid())
				rec.Data.Fields["fd_cnt"] = strconv.FormatInt(int64(fds), 10)
				rec.Data.Fields["started_at"] = strconv.FormatInt(startAt, 10)
			}
			rec.Data.Fields["du"] = strconv.FormatUint(resource.GetDirSize(plg.GetWorkingDirectory(), ""), 10)
			RxSpeed, TxSpeed, RxTPS, TxTPS := plg.GetState()
			rec.Data.Fields["rx_tps"] = strconv.FormatFloat(RxTPS, 'f', 8, 64)
			rec.Data.Fields["tx_tps"] = strconv.FormatFloat(TxTPS, 'f', 8, 64)
			rec.Data.Fields["rx_speed"] = strconv.FormatFloat(RxSpeed, 'f', 8, 64)
			rec.Data.Fields["tx_speed"] = strconv.FormatFloat(TxSpeed, 'f', 8, 64)
			core.DefaultTrans.Transmission(rec, false)
		}
	}
}
