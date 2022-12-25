package transport

import (
	"agent/agent"
	"agent/proto"
	"agent/transport/pool"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chriskaliX/SDK/config"
	"github.com/chriskaliX/SDK/transport/protocol"
	"go.uber.org/zap"
)

var (
	ErrBufferOverflow = errors.New("buffer overflow")
	ErrAgentDataType  = errors.New("agent datatype is not support")
)

var (
	PluginTaskChan   = make(chan *proto.Task)
	PluginConfigChan = make(chan map[string]*proto.Config)
)

const size = 8186 // remain 6 space for importance, always available

var DefaultTrans = New()

type Transfer struct {
	mu         sync.Mutex
	buf        [8192]*proto.Record
	offset     int
	txCnt      uint64
	rxCnt      uint64
	updateTime time.Time
}

func New() *Transfer {
	return &Transfer{
		buf:        [8192]*proto.Record{},
		updateTime: time.Now(),
	}
}

// Save the record to the buffer, control the buffer
func (t *Transfer) Transmission(rec *proto.Record, important bool) (err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.offset >= size {
		if important && t.offset < len(t.buf) {
			t.buf[t.offset] = rec
			t.offset++
		}
		err = ErrBufferOverflow
		return
	}
	t.buf[t.offset] = rec
	t.offset++
	return
}

func (t *Transfer) TransmissionSDK(rec protocol.ProtoType, important bool) (err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.offset >= size {
		if important && t.offset < len(t.buf) {
			t.buf[t.offset] = rec.(*proto.Record)
			t.offset++
		}
		err = ErrBufferOverflow
		return
	}
	t.buf[t.offset] = rec.(*proto.Record)
	t.offset++
	return
}

// Send the record from buffer
func (t *Transfer) Send(client proto.Transfer_TransferClient) (err error) {
	// use lock carefully, unlock the field if we need
	t.mu.Lock()
	if t.offset == 0 {
		t.mu.Unlock()
		return
	}
	recs := make([]*proto.Record, t.offset)
	copy(recs, t.buf[:t.offset]) // copy, for reference
	t.offset = 0
	t.mu.Unlock()
	// Send the copy
	if err = client.Send(&proto.PackagedData{
		Records:      recs,
		AgentId:      agent.ID,
		IntranetIpv4: agent.PrivateIPv4.Load().([]string),
		IntranetIpv6: agent.PrivateIPv6.Load().([]string),
		ExtranetIpv4: agent.PublicIPv4.Load().([]string),
		ExtranetIpv6: agent.PublicIPv6.Load().([]string),
		Hostname:     agent.Hostname.Load().(string),
		Version:      agent.Version,
		Product:      agent.Product,
	}); err != nil {
		zap.S().Error(err)
	} else {
		atomic.AddUint64(&t.txCnt, uint64(len(recs)))
	}
	for _, rec := range recs {
		pool.Put(rec)
	}
	return
}

func (t *Transfer) Receive(client proto.Transfer_TransferClient) (err error) {
	cmd, err := client.Recv()
	if err != nil {
		return
	}
	zap.S().Info("command received")
	atomic.AddUint64(&t.rxCnt, 1)
	// resolve task & config
	t.resolveTask(cmd)
	agent.SetRunning()
	t.resolveConfig(cmd)
	return
}

func (t *Transfer) GetState(now time.Time) (txTPS, rxTPS float64) {
	instant := now.Sub(t.updateTime).Seconds()
	if instant != 0 {
		txTPS = float64(atomic.SwapUint64(&t.txCnt, 0)) / float64(instant)
		rxTPS = float64(atomic.SwapUint64(&t.rxCnt, 0)) / float64(instant)
	}
	t.updateTime = now
	return
}

func (t *Transfer) resolveConfig(cmd *proto.Command) (err error) {
	if cmd == nil || cmd.Configs == nil {
		return
	}
	configs := map[string]*proto.Config{}
	for _, config := range cmd.Configs {
		configs[config.Name] = config
	}
	if config, ok := configs[agent.Product]; ok && config.Version != agent.Version {
		zap.S().Infof("agent will update:current version %v -> expected version %v", agent.Version, config.Version)
		if err = agent.Update(*config); err == nil {
			zap.S().Info("agent update successfully")
			agent.Cancel()
			return
		}
		zap.S().Error("agent update failed:", err)
		agent.SetAbnormal(fmt.Sprintf("agent update failed: %s", err))
	}
	delete(configs, agent.Product)
	PluginConfigChan <- configs
	return
}

func (t *Transfer) resolveTask(cmd *proto.Command) (err error) {
	// resolve task by it's name
	if cmd == nil || cmd.Task == nil {
		return
	}
	switch cmd.Task.ObjectName {
	case agent.Product:
		switch cmd.Task.DataType {
		case config.TaskShutdown:
			zap.S().Info("agent shutdown is called")
			agent.Cancel()
			return
		case config.TaskRestart:
		case config.TaskSetenv:
		default:
			zap.S().Error("resolveTask Agent DataType not supported: ", cmd.Task.DataType)
			return ErrAgentDataType
		}
	default:
		PluginTaskChan <- cmd.Task
	}
	return
}
