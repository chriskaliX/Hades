package user

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"hades-ebpf/user/decoder"
	_ "hades-ebpf/user/event"
	"hades-ebpf/user/filter"
	"hades-ebpf/user/share"
	"hades-ebpf/utils"
	"math"
	"os"
	"strconv"
	"syscall"
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
const confDenyBPF uint32 = 0

// Task
const (
	TaskDisableProbe   = 7
	TaskEnableProbe    = 8
	TaskWhiteList      = 9
	TaskEnableDenyBPF  = 10
	TaskDisableDenyBPF = 11
)

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

// New a driver with pre-set map and options
func NewDriver(s SDK.ISandbox) (*Driver, error) {
	driver := &Driver{Sandbox: s}
	// init ebpfmanager with maps and perf_events
	driver.Manager = &manager.Manager{
		PerfMaps: []*manager.PerfMap{
			{Map: manager.Map{Name: "exec_events"}, PerfMapOptions: manager.PerfMapOptions{
				PerfRingBufferSize: 256 * os.Getpagesize(),
				DataHandler:        driver.dataHandler,
				LostHandler:        driver.lostHandler,
			}},
			// network events, for now, only honeypot was introduced
			{Map: manager.Map{Name: "net_events"}, PerfMapOptions: manager.PerfMapOptions{
				PerfRingBufferSize: 256 * os.Getpagesize(),
				DataHandler:        driver.dataHandler,
				LostHandler:        driver.lostHandler,
			}},
		},
		Maps: []*manager.Map{
			{Name: configMap},
			{Name: "pid_filter", Contents: []ebpf.MapKV{{
				Key: uint32(os.Getpid()), Value: uint32(0),
			}}},
		},
	}

	for _, event := range decoder.Events {
		driver.Manager.Probes = append(driver.Manager.Probes, event.GetProbes()...)
		if event.GetMaps() != nil {
			driver.Manager.Maps = append(driver.Manager.Maps, event.GetMaps()...)
		}
	}

	var stext, etext, pgid uint64
	// Init options with constant value updated
	if _stext := utils.Ksyms.Get("_stext"); _stext != nil {
		stext = _stext.Address
	}
	if _etext := utils.Ksyms.Get("_etext"); _etext != nil {
		etext = _etext.Address
	}
	if _pgid, err := syscall.Getpgid(os.Getpid()); err == nil {
		pgid = uint64(_pgid)
	}

	err := driver.Manager.InitWithOptions(
		bytes.NewReader(_bytecode),
		manager.Options{
			DefaultKProbeMaxActive: 512,
			VerifierOptions: ebpf.CollectionOptions{
				Programs: ebpf.ProgramOptions{LogSize: 1 * 1024 * 1024},
			},
			RLimit: &unix.Rlimit{
				Cur: math.MaxUint64,
				Max: math.MaxUint64,
			},
			// Init added, be careful that bpf_printk
			ConstantEditors: []manager.ConstantEditor{
				{Name: "hades_stext", Value: stext},
				{Name: "hades_etext", Value: etext},
				{Name: "hades_pgid", Value: pgid},
			},
		})

	driver.context, driver.cancel = context.WithCancel(s.Context())
	return driver, err
}

func (d *Driver) Start() error { return d.Manager.Start() }

// init the driver with default value
func (d *Driver) PostRun() (err error) {
	zap.S().Info("ebpfdriver init configuration has been loaded")
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

func (d *Driver) StartProbe(UID string) (err error) {
	for _, probe := range d.Manager.Probes {
		if UID == probe.UID {
			return probe.Init(d.Manager)
		}
	}
	return fmt.Errorf("UID %s not found", UID)
}

func (d *Driver) Stop() error {
	zap.S().Info("driver stop is called")
	d.cancel()
	return d.Manager.Stop(manager.CleanAll)
}

func (d *Driver) taskResolve() {
	for {
		select {
		case <-d.context.Done():
			return
		default:
			task := d.Sandbox.RecvTask()
			switch task.DataType {
			case TaskDisableProbe:
				d.Close(task.Data)
			case TaskEnableProbe:
				d.StartProbe(task.Data)
			case TaskWhiteList:
				if err := filter.LoadConfigFromTask(task); err != nil {
					zap.S().Error(err)
				}
			case TaskEnableDenyBPF:
				if err := d.mapUpdate(configMap, confDenyBPF, uint64(1)); err != nil {
					zap.S().Error(err)
				}
			case TaskDisableDenyBPF:
				if err := d.mapUpdate(configMap, confDenyBPF, uint64(0)); err != nil {
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
	var eventDecoder decoder.Event
	// get and decode the context
	ctx, err := decoder.DefaultDecoder.DecodeContext()
	if err != nil {
		return
	}
	// get the event and set context into event
	eventDecoder = decoder.Events[ctx.Type]
	// value count
	if err = eventDecoder.DecodeEvent(decoder.DefaultDecoder); err != nil {
		if err == decoder.ErrFilter {
			return
		} else if err == decoder.ErrIgnore {
			return
		}
		zap.S().Errorf("decode event error: %s", err)
		return
	}
	// Fillup the context by the values that Event offers
	ctx.FillContext(eventDecoder.Name(), eventDecoder.GetExe())
	result, err := decoder.MarshalJson(eventDecoder, ctx)
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
	d.Sandbox.SendRecord(rec)
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

// internal map operation
func (d *Driver) mapUpdate(name string, key uint32, value interface{}) error {
	bpfmap, found, err := d.Manager.GetMap(name)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("bpfmap %s not found", name)
	}
	return bpfmap.Update(key, value, ebpf.UpdateAny)
}
