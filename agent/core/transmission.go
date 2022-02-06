package core

import (
	"agent/agent"
	"agent/core/pool"
	"agent/host"
	"agent/plugin"
	"agent/proto"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

var (
	ErrBufferOverflow = errors.New("buffer overflow")
	DefaultTrans      = &Trans{
		buf:        [8208]interface{}{},
		offset:     0,
		updateTime: time.Now(),
	}
)

type Trans struct {
	mu         sync.Mutex
	buf        [8208]interface{} // max buffer size 8192 + 16(for important)
	offset     int
	txCnt      uint64
	rxCnt      uint64
	updateTime time.Time
}

// The `tolerate` in Elkeid, make sure the important data is transported and insert into the front by replacing
// the Buf[0], which I think is not as good as I want...
func (t *Trans) Transmission(rec interface{}, importance bool) (err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.offset < len(t.buf) {
		// when buffer is not full(8192)
		if t.offset < 8192 || importance {
			t.buf[t.offset] = rec
			t.offset++
			return
		}
	}
	// when buffer is full
	err = ErrBufferOverflow
	return
}

func (tr *Trans) Send(client proto.Transfer_TransferClient) (err error) {
	tr.mu.Lock()
	if tr.offset != 0 {
		nbuf := make([]*proto.EncodedRecord, 0, tr.offset)
		for _, v := range tr.buf[:tr.offset] {
			switch t := v.(type) {
			case *proto.EncodedRecord:
				nbuf = append(nbuf, t)
			case *proto.Record:
				data, _ := t.Data.Marshal()
				rec := pool.Get()
				rec.DataType = t.DataType
				rec.Timestamp = t.Timestamp
				rec.Data = data
				nbuf = append(nbuf, rec)
			}
		}
		err = client.Send(&proto.PackagedData{
			Records:      nbuf,
			AgentId:      agent.ID,
			IntranetIpv4: host.PrivateIPv4.Load().([]string),
			IntranetIpv6: host.PrivateIPv6.Load().([]string),
			ExtranetIpv4: host.PublicIPv4.Load().([]string),
			ExtranetIpv6: host.PublicIPv6.Load().([]string),
			Hostname:     host.Hostname.Load().(string),
			Version:      agent.Version,
			Product:      agent.Product,
		})
		// a little bit weird, but understandable
		for _, v := range nbuf {
			v.Data = v.Data[:0]
			pool.Put(v)
		}
		if err == nil {
			atomic.AddUint64(&tr.txCnt, uint64(tr.offset))
			tr.offset = 0
		} else {
			tr.mu.Unlock()
			return
		}
		tr.mu.Unlock()
	}
	return
}

func (tr *Trans) Receive(client proto.Transfer_TransferClient) (err error) {
	cmd, err := client.Recv()
	if err != nil {
		return
	}
	zap.S().Info("received command")
	atomic.AddUint64(&tr.rxCnt, 1)
	// if task is available, handle task
	if cmd.Task != nil {
		// agent task
		// plugin task
	}
	// if configuration available, handle config
	cfgs := map[string]*proto.Config{}
	for _, config := range cmd.Configs {
		cfgs[config.Name] = config
	}
	// TODO:agent self-update, not as I expected. Understand now, update later
	if cfg, ok := cfgs[agent.Product]; ok && cfg.Version != agent.Version {
		zap.S().Infof("agent will update:current version %v -> expected version %v", agent.Version, cfg.Version)
		err = agent.Update(*cfg)
		if err == nil {
			zap.S().Info("update successfully")
			agent.Cancel()
			return
		} else {
			zap.S().Error("update failed:", err)
		}
	}
	delete(cfgs, agent.Product)
	// sync Plugin
	if e := plugin.DefaultManager.Sync(cfgs); e != nil {
		zap.S().Error(err)
	}
	return
}

func (tr *Trans) GetState(now time.Time) (txTPS, rxTPS float64) {
	instant := now.Sub(tr.updateTime).Seconds()
	if instant != 0 {
		txTPS = float64(atomic.SwapUint64(&tr.txCnt, 0)) / float64(instant)
		rxTPS = float64(atomic.SwapUint64(&tr.rxCnt, 0)) / float64(instant)
	}
	tr.updateTime = now
	return
}
