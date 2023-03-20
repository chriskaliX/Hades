package user

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hades-ebpf/conf"
	"hades-ebpf/user/decoder"
	_ "hades-ebpf/user/event"
	"hades-ebpf/user/filter"
	"hades-ebpf/utils"
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"os"
	"strconv"
	"syscall"
	"time"

	utilEbpf "hades-ebpf/utils/ebpf"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	manager "github.com/ehids/ebpfmanager"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/version"

	_ "embed"

	"github.com/shirou/gopsutil/host"
)

//go:embed hades_ebpf_driver.o
var bytecode []byte

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
	status  bool
}

// New a driver with pre-set map and options
func NewDriver(s SDK.ISandbox) (*Driver, error) {
	// By default, using build-in core bytecode
	if ok, err := utilEbpf.IsEnableBTF(); err == nil && ok {
		zap.S().Info("BTF enabled, using hardcode bytecode")
	} else {
		// For the safety here, use RSA and AES to encrypt and check the whole file
		driverName, err := downloadBytecode()
		if err != nil {
			return nil, err
		}
		bytecode, err := ioutil.ReadFile(driverName)
		if err != nil {
			return nil, err
		}
		zap.S().Infof("%s load success, length: %d", driverName, len(bytecode))
	}

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
		},
	}

	// if isEnableRingbuf() {
	// 	driver.Manager.PerfMaps = append(driver.Manager.PerfMaps, &manager.PerfMap{
	// 		Map: manager.Map{Name: "exec_events_ringbuf"},
	// 		PerfMapOptions: manager.PerfMapOptions{
	// 			PerfRingBufferSize: 256 * os.Getpagesize(),
	// 			DataHandler:        driver.dataHandler,
	// 			LostHandler:        driver.lostHandler,
	// 		},
	// 	})
	// }

	if !conf.Debug {
		driver.Manager.Maps = append(driver.Manager.Maps, &manager.Map{Name: "pid_filter", Contents: []ebpf.MapKV{{
			Key: uint32(os.Getpid()), Value: uint32(0),
		}}})
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
	if _pgid, err := syscall.Getpgid(os.Getpid()); err == nil && !conf.Debug {
		pgid = uint64(_pgid)
	}

	if err := driver.Manager.InitWithOptions(
		bytes.NewReader(bytecode),
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
		}); err != nil {
		return nil, err
	}

	driver.context, driver.cancel = context.WithCancel(context.Background())
	return driver, nil
}

func (d *Driver) Status() bool {
	return d.status
}

func (d *Driver) Start() error {
	err := d.Manager.Start()
	if err == nil {
		d.status = true
	}
	return err
}

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
		if conf.Debug {
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
	if err := d.Manager.Stop(manager.CleanAll); err != nil {
		return err
	}
	d.status = false
	return nil
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
		DataType: int32(ctx.Type),
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

// Here is the other thing, since CO-RE is really useful, we can still embed the
// CO-RE bytecode into the driver binary, but we do check the BTF enabled option,
// and download the bytecode to override the embeded bytecode.
func downloadBytecode() (driverName string, err error) {
	// TODO: load driver bytecode dynamiclly by downloading, make the
	// sha256 of ebpfdriver userspace stay the same
	//
	// By default, if BTF is enabled, use CORE version driver
	var driverType string
	if _, err := btf.LoadKernelSpec(); err != nil {
		driverType = "nocore"
	} else {
		driverType = "core"
	}

	var arch string
	arch, _ = host.KernelArch()
	switch arch {
	case "x86_64":
		arch = "amd64"
	case "aarch64":
		arch = "arm64"
	}

	switch driverType {
	case "core":
		driverName = fmt.Sprintf("hades_ebpf_driver_%s_%s_%s.o", conf.VERSION, driverType, arch)
	case "nocore":
		version, _ := host.KernelVersion()
		driverName = fmt.Sprintf("hades_ebpf_driver_%s_%s_%s_%s.o", conf.VERSION, driverType, arch, version)
	}
	zap.S().Infof("driver name: %s", driverName)
	// TODO: Dynamically load, need to make sure the sha256 is correct. Or a replacement would easily attack this
	if conf.Debug {
		driverName = "hades_ebpf_driver.o"
		return
	}
	// check local
	if _, err = os.Stat(driverName); err == nil {
		zap.S().Infof("driver %s exists", driverName)
		return
	}
	// not exist, download the driver
	for i := 0; i < 15; i++ {
		if err := download(driverName); err != nil {
			zap.S().Errorf("download driver failed: %s", err.Error())
			time.Sleep(60 * time.Second)
			continue
		} else {
			break
		}
	}
	return
}

func download(driverName string) (err error) {
	// In Elkeid v1.9.1, only Timeout is different from DefaultTransport.
	// Before v1.9.1 the timeout was controlled by subctx, now it is
	// controlled by client itself.
	client := &http.Client{
		Transport: http.DefaultTransport,
		Timeout:   30 * time.Second,
	}
	url := conf.DOWNLOAD_URL + driverName
	var req *http.Request
	var resp *http.Response
	if req, err = http.NewRequest("GET", url, nil); err != nil {
		return
	}
	if resp, err = client.Do(req); err != nil {
		return
	}
	if !(resp.StatusCode >= 200 && resp.StatusCode < 300) {
		err = errors.New("http error: " + resp.Status)
		return
	}
	resp.Body = http.MaxBytesReader(nil, resp.Body, 512*1024*1024)
	save(driverName, resp.Body)
	resp.Body.Close()
	return
}

func save(dst string, r io.Reader) (err error) {
	var f *os.File
	if f, err = os.OpenFile(dst, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o0600); err != nil {
		return
	}
	defer f.Close()
	if _, err = io.Copy(f, r); err != nil {
		return err
	}
	return
}

func isEnableRingbuf() bool {
	var ringBufMinKV, _ = version.ParseGeneric("5.8.0")
	version, err := version.ParseGeneric(utils.KernelVersion)
	if err != nil {
		return false
	}
	return !version.LessThan(ringBufMinKV)
}
