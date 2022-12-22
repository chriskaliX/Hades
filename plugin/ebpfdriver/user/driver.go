package user

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"hades-ebpf/user/decoder"
	_ "hades-ebpf/user/event"
	"hades-ebpf/user/helper"
	"hades-ebpf/user/share"
	"math"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/cilium/ebpf"
	manager "github.com/ehids/ebpfmanager"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

//go:embed hades_ebpf_driver.o
var _bytecode []byte

// config
const configMap = "config_map"
const conf_DENY_BPF uint32 = 0
const conf_STEXT uint32 = 1
const conf_ETEXT uint32 = 2

// filters
const filterPid = "pid_filter"

// Task
const EnableDenyBPF = 10
const DisableDenyBPF = 11

var rawdata = make(map[string]string, 1)

// Driver contains the ebpfmanager and eventDecoder. By default, Driver
// is a singleton and it's not thread-safe
type Driver struct {
	Sandbox SDK.ISandbox
	Manager *manager.Manager
	context context.Context
	cancel  context.CancelFunc
	cronM   *cron.Cron
	// driver state monitor
	filterCount atomic.Value
	dropCount   atomic.Value
	transCount  atomic.Value
}

// New a driver with pre-set map and options
func NewDriver(s SDK.ISandbox) (*Driver, error) {
	driver := &Driver{}
	driver.Sandbox = s
	// init ebpfmanager with maps and perf_events
	driver.Manager = &manager.Manager{
		PerfMaps: []*manager.PerfMap{
			{
				Map: manager.Map{Name: "exec_events"},
				PerfMapOptions: manager.PerfMapOptions{
					PerfRingBufferSize: 256 * os.Getpagesize(),
					DataHandler:        driver.dataHandler,
					LostHandler:        driver.lostHandler,
				},
			},
			{
				Map: manager.Map{Name: "net_events"},
				PerfMapOptions: manager.PerfMapOptions{
					PerfRingBufferSize: 256 * os.Getpagesize(),
					DataHandler:        driver.dataHandler,
					LostHandler:        driver.lostHandler,
				},
			},
		},
		Maps: []*manager.Map{
			{Name: configMap},
			{Name: filterPid},
		},
	}
	for _, event := range decoder.Events {
		driver.Manager.Probes = append(driver.Manager.Probes, event.GetProbes()...)
		if event.GetMaps() != nil {
			driver.Manager.Maps = append(driver.Manager.Maps, event.GetMaps()...)
		}
	}
	err := driver.Manager.InitWithOptions(bytes.NewReader(_bytecode), manager.Options{
		DefaultKProbeMaxActive: 512,
		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: 1 * 1024 * 1024,
			},
		},
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	})
	driver.context, driver.cancel = context.WithCancel(s.Context())
	return driver, err
}

func (d *Driver) Start() error { return d.Manager.Start() }

// Init the driver with default value
func (d *Driver) PostRun() (err error) {
	// Get Pid filter
	if err := helper.MapUpdate(d.Manager, filterPid, uint32(os.Getpid()), uint32(0)); err != nil {
		zap.S().Error(err)
	}
	// STEXT ETEXT for rootkit detection
	if _stext := helper.Ksyms.Get("_stext"); _stext != nil {
		if err := helper.MapUpdate(d.Manager, configMap, conf_STEXT, _stext.Address); err != nil {
			zap.S().Error(err)
		}
	}
	if _etext := helper.Ksyms.Get("_etext"); _etext != nil {
		if err := helper.MapUpdate(d.Manager, configMap, conf_ETEXT, _etext.Address); err != nil {
			zap.S().Error(err)
		}
	}
	zap.S().Info("init configuration has been loaded")
	// By default, we do not ban BPF program unless you choose on this..
	d.cronM = cron.New(cron.WithSeconds())
	// Regist the cronjobs of the event
	for _, event := range decoder.Events {
		interval, cronFunc := event.RegistCron()
		if cronFunc == nil {
			continue
		}
		if share.Debug {
			interval = "*/20 * * * * *"
		}
		if _, err := d.cronM.AddFunc(interval, func() {
			cronFunc(d.Manager)
		}); err != nil {
			zap.S().Error(err)
		}
	}
	d.cronM.Start()
	go d.taskResolve()
	return nil
}

// close probes by uid
func (d *Driver) Close(UID string) (err error) {
	for _, probe := range d.Manager.Probes {
		if UID == probe.UID {
			return probe.Stop()
		}
	}
	return fmt.Errorf("UID %s not found", UID)
}

func (d *Driver) Stop() error {
	zap.S().Info("driver stop is called")
	d.cancel()
	return d.Manager.Stop(manager.CleanAll)
}

func (d *Driver) Filter() {}

func (d *Driver) taskResolve() {
	for {
		select {
		case <-d.context.Done():
		default:
			task := d.Sandbox.RecvTask()
			switch task.DataType {
			case EnableDenyBPF:
				if err := helper.MapUpdate(d.Manager, configMap, conf_DENY_BPF, uint64(1)); err != nil {
					zap.S().Error(err)
				}
			case DisableDenyBPF:
				if err := helper.MapUpdate(d.Manager, configMap, conf_DENY_BPF, uint64(0)); err != nil {
					zap.S().Error(err)
				}
			}
			time.Sleep(time.Second)
		}
	}
}

// dataHandler handles the data from eBPF kernel space
func (d *Driver) dataHandler(cpu int, data []byte, perfmap *manager.PerfMap, manager *manager.Manager) {
	// set into buffer
	decoder.DefaultDecoder.SetBuffer(data)
	// variable init
	var eventDecoder decoder.Event
	var ctx *decoder.Context
	var err error
	var result string
	// TODO: only for temporary
	if perfmap.Name == "exec_events" {
		// get and decode the context
		ctx, err = decoder.DefaultDecoder.DecodeContext()
		if err != nil {
			return
		}
		// get the event and set context into event
		eventDecoder = decoder.Events[ctx.Type]
		// Fillup the context by the values that Event offers
		ctx.FillContext(eventDecoder.Name(), eventDecoder.GetExe())
	} else {
		// TODO: for now, only net_events, temporary hardcode
		eventDecoder = decoder.Events[3000]
	}
	if err = eventDecoder.DecodeEvent(decoder.DefaultDecoder); err != nil {
		if err == decoder.ErrFilter || err == decoder.ErrIgnore {
			return
		}
		zap.S().Errorf("decode event error: %s", err)
		return
	}
	// marshal the data
	result, err = decoder.MarshalJson(eventDecoder, ctx)
	if err != nil {
		zap.S().Error(err)
		return
	}
	rawdata["data"] = result
	// send the record
	rec := &protocol.Record{
		DataType: 1000,
		Data: &protocol.Payload{
			Fields: rawdata,
		},
	}
	if err = d.Sandbox.SendRecord(rec); err != nil {
		zap.S().Error(err)
	}
}

// lostHandler handles the data for errors
func (d *Driver) lostHandler(CPU int, count uint64, perfMap *manager.PerfMap, manager *manager.Manager) {
	rawdata["data"] = strconv.FormatUint(count, 10)
	rec := &protocol.Record{
		DataType: 999,
		Data: &protocol.Payload{
			Fields: rawdata,
		},
	}
	d.Sandbox.SendRecord(rec)
}
