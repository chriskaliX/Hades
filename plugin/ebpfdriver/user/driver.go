package user

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"hades-ebpf/user/decoder"
	"hades-ebpf/user/event"
	"math"
	"os"
	"strconv"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/cilium/ebpf"
	manager "github.com/ehids/ebpfmanager"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

//go:embed hades_ebpf_driver.o
var _bytecode []byte

const configMap = "config_map"
const eventMap = "exec_events"

var rawdata = make(map[string]string, 1)

// Driver contains the ebpfmanager and eventDecoder. By default, Driver
// is a singleton and it's not thread-safe
type Driver struct {
	Sandbox SDK.ISandbox
	Manager *manager.Manager
	context context.Context
	cancel  context.CancelFunc
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
		Maps: []*manager.Map{{Name: configMap}},
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
				LogSize: 1024 * 1024,
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
func (d *Driver) Init() error {
	// Init ConfigMap with default value
	configMap, found, err := d.Manager.GetMap(configMap)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%s not found", configMap)
	}
	/* enum hades_ebpf_config {
	 *	 CONFIG_HADES_PID,
	 *	 CONFIG_FILTERS
	 *};*/
	var syscall_index uint32 = 0
	var pid uint32 = uint32(os.Getpid())
	err = configMap.Update(syscall_index, pid, ebpf.UpdateAny)
	if err != nil {
		return err
	}
	// Regist the cronjobs of the event
	for _, event := range decoder.Events {
		cronFunc, ticker := event.RegistCron()
		if cronFunc != nil && ticker != nil {
			go func() {
				for {
					select {
					case <-ticker.C:
						cronFunc(d.Manager)
					case <-d.context.Done():
						return
					}
				}
			}()
		}
	}

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
