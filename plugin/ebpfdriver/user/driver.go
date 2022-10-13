package user

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"hades-ebpf/user/decoder"
	"hades-ebpf/user/event"
	"hades-ebpf/user/helper"
	"hades-ebpf/user/share"
	"math"
	"os"
	"strconv"
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
const eventMap = "exec_events"

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
}

type IDriver interface {
	Start() error
	PostRun() error
	Close(string) error
	Stop() error
}

// New a driver with pre-set map and options
func NewDriver(s SDK.ISandbox) (*Driver, error) {
	driver := &Driver{}
	driver.Sandbox = s
	// init ebpfmanager with maps and perf_events
	driver.Manager = &manager.Manager{
		PerfMaps: []*manager.PerfMap{
			{
				Map: manager.Map{Name: eventMap},
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
	// Get all registed events probes and maps, add into the manager
	for _, event := range decoder.Events {
		driver.Manager.Probes = append(driver.Manager.Probes, event.GetProbes()...)
		driver.Manager.Maps = append(driver.Manager.Maps, event.GetMaps()...)
	}
	// init manager with options
	// TODO: High CPU performance here
	// github.com/ehids/ebpfmanager.(*Probe).Init
	// github.com/ehids/ebpfmanager.getSyscallFnNameWithKallsyms
	err := driver.Manager.InitWithOptions(bytes.NewReader(_bytecode), manager.Options{
		DefaultKProbeMaxActive: 512,
		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				// The logsize is just test value for now
				LogSize: 2 * 1024 * 1024,
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

func (d *Driver) Start() error {
	return d.Manager.Start()
}

// Init the driver with default value
func (d *Driver) PostRun() (err error) {
	// Get Pid filter
	if err := helper.MapUpdate(d.Manager, filterPid, uint32(os.Getpid()), uint32(0)); err != nil {
		zap.S().Error(err)
	}
	// By default, we do not ban BPF program unless you choose on this..
	d.cronM = cron.New(cron.WithSeconds())
	// Regist the cronjobs of the event
	for _, event := range decoder.Events {
		interval, cronFunc := event.RegistCron()
		if cronFunc == nil {
			continue
		}
		if share.Debug {
			interval = "*/10 * * * * *"
		}
		if _, err := d.cronM.AddFunc(interval, func() {
			cronFunc(d.Manager)
		}); err != nil {
			zap.S().Error(err)
		}
	}
	d.cronM.Start()

	go d.taskResolve()
	// TODO: filters are not added for now
	return nil
}

// close probes by uid
func (d *Driver) Close(UID string) (err error) {
	for _, probe := range d.Manager.Probes {
		if UID == probe.UID {
			return probe.Stop()
		}
	}
	_, err = fmt.Printf("UID %s not found", UID)
	return err
}

func (d *Driver) Stop() error {
	d.cancel()
	return d.Manager.Stop(manager.CleanAll)
}

func (d *Driver) Filter() {}

func (d *Driver) taskResolve() {
	for {
		task := d.Sandbox.RecvTask()
		switch task.DataType {
		case EnableDenyBPF:
			if err := helper.MapUpdate(d.Manager, configMap, conf_DENY_BPF, uint32(1)); err != nil {
				zap.S().Error(err)
			}
		case DisableDenyBPF:
			if err := helper.MapUpdate(d.Manager, configMap, conf_DENY_BPF, uint32(0)); err != nil {
				zap.S().Error(err)
			}
		}
		time.Sleep(time.Second)
	}
}

// dataHandler handles the data from eBPF kernel space
func (d *Driver) dataHandler(cpu int, data []byte, perfmap *manager.PerfMap, manager *manager.Manager) {
	// get and decode the context
	ctx := decoder.NewContext()
	decoder.DefaultDecoder.ReInit(data)
	err := ctx.DecodeContext(decoder.DefaultDecoder)
	if err != nil {
		return
	}
	defer decoder.PutContext(ctx)
	// get the event and set context into event
	eventDecoder := decoder.Events[ctx.Type]
	eventDecoder.SetContext(ctx)
	err = eventDecoder.DecodeEvent(decoder.DefaultDecoder)
	if err == event.ErrFilter {
		// it's been filtered
		return
	}
	if err != nil {
		// Ignore
		if err == event.ErrIgnore {
			return
		}
		zap.S().Errorf("error: %s", err)
		return
	}
	// Fillup the context by the values that Event offers
	ctx.FillContext(eventDecoder.Name(), eventDecoder.GetExe())
	// marshal the data
	result, err := decoder.MarshalJson(eventDecoder)
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
	rawdata := make(map[string]string)
	rawdata["data"] = strconv.FormatUint(count, 10)
	rec := &protocol.Record{
		DataType: 999,
		Data: &protocol.Payload{
			Fields: rawdata,
		},
	}
	d.Sandbox.SendRecord(rec)
}
