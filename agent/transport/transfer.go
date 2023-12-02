package transport

import (
	"github.com/chriskaliX/Hades/agent/agent"
	"github.com/chriskaliX/Hades/agent/proto"
	"github.com/chriskaliX/Hades/agent/transport/pool"
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

// The channel to dispatch to plugin
var (
	PluginTaskChan   = make(chan *proto.Task)
	PluginConfigChan = make(chan map[string]*proto.Config)
)

const size = 8186 // remain 6 space for importance, always available

var Trans = NewTransfer()

type Transfer struct {
	mu         sync.Mutex
	buf        [8192]*proto.Record
	offset     int
	txCnt      uint64
	rxCnt      uint64
	updateTime time.Time
}

func NewTransfer() *Transfer {
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

// TransmissionSDK is an wrapper to satisfy the SDK interface
func (t *Transfer) TransmissionSDK(rec protocol.ProtoType, important bool) (err error) {
	return t.Transmission(rec.(*proto.Record), important)
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
	}); err == nil {
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
	// precheck cmd
	if cmd == nil {
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
	if cmd.Configs == nil {
		return
	}
	configs := map[string]*proto.Config{}
	for _, config := range cmd.Configs {
		configs[config.Name] = config
	}
	if config, ok := configs[agent.Product]; ok && config.Version != agent.Version {
		zap.S().Infof("agent will update from version %v to version %v", agent.Version, config.Version)
		if err = agent.Update(*config); err == nil {
			zap.S().Info("agent update successfully")
			agent.Cancel()
			return
		}
		zap.S().Errorf("agent update failed: %s", err.Error())
		agent.SetAbnormal(fmt.Sprintf("agent update failed: %s", err.Error()))
	}
	delete(configs, agent.Product)
	select {
	case PluginConfigChan <- configs:
	default:
		err = fmt.Errorf("plugin configchan is syncing or is cancelled")
		zap.S().Error(err.Error())
	}
	return
}

func (t *Transfer) resolveTask(cmd *proto.Command) (err error) {
	if cmd.Task == nil {
		return
	}
	if cmd.Task.ObjectName == agent.Product {
		switch cmd.Task.DataType {
		// according to the service, restart will be 45 secs in systemd based daemon
		// crontab is used in sysvinit to keep the agent always available
		case config.TaskShutdown, config.TaskRestart:
			zap.S().Info("agent shutdown is called")
			TaskSuccess(cmd.Task.Token, "agent shutdown is called")
			agent.Cancel()
			return
		case config.TaskSetenv:
		default:
			TaskError(cmd.Task.Token, fmt.Sprintf("agent datatype %d is not supported", cmd.Task.DataType))
			return ErrAgentDataType
		}
	}
	select {
	case PluginTaskChan <- cmd.Task:
	default:
		err = fmt.Errorf("plugin taskchan is syncing or is cancelled")
		TaskError(cmd.Task.Token, err.Error())
	}
	return
}

func TaskSuccess(token string, msg string) {
	zap.S().Info(token, msg)
	Trans.Transmission(&proto.Record{
		DataType:  5100,
		Timestamp: time.Now().Unix(),
		Data: &proto.Payload{
			Fields: map[string]string{
				"token":  token,
				"msg":    msg,
				"status": "success",
			},
		},
	}, true)
}

func TaskError(token string, msg string) {
	zap.S().Error(token, msg)
	Trans.Transmission(&proto.Record{
		DataType:  5100,
		Timestamp: time.Now().Unix(),
		Data: &proto.Payload{
			Fields: map[string]string{
				"token":  token,
				"msg":    msg,
				"status": "fail",
			},
		},
	}, true)
}
