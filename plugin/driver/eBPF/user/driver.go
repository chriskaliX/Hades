package user

import (
	"bytes"
	_ "embed"
	"fmt"
	"hades-ebpf/user/decoder"
	"hades-ebpf/user/event"
	"hades-ebpf/user/share"
	"math"
	"os"
	"strconv"

	"github.com/chriskaliX/plugin"
	"github.com/cilium/ebpf"
	manager "github.com/ehids/ebpfmanager"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

var Env = "prod"

//go:embed hades_ebpf_driver.o
var _bytecode []byte

var rawdata = make(map[string]string, 1)

var DefaultDriver = &Driver{}

type Driver struct {
	Manager      *manager.Manager
	eventDecoder decoder.Event
}

func (d *Driver) Init() (err error) {
	d.Manager = &manager.Manager{}
	events := decoder.GetEvents()
	// Get all Probes and Maps
	for _, event := range events {
		d.Manager.Probes = append(d.Manager.Probes, event.GetProbe()...)
		d.Manager.Maps = append(d.Manager.Maps, event.GetMaps()...)
	}

	/*
	 * Init events and their ebpfmanager mapping
	 */
	// Regist main events which should not be regist in events
	d.Manager.PerfMaps = []*manager.PerfMap{
		{
			Map: manager.Map{
				Name: "exec_events",
			},
			PerfMapOptions: manager.PerfMapOptions{
				PerfRingBufferSize: 256 * os.Getpagesize(),
				DataHandler:        d.dataHandler,
				LostHandler:        d.lostHandler,
			},
		},
	}
	// Regist common maps which is globally used
	d.Manager.Maps = append(d.Manager.Maps, []*manager.Map{
		{
			Name: "config_map",
		},
	}...)
	// init manager options, TODO: LogSize is test only now.
	err = d.Manager.InitWithOptions(bytes.NewReader(_bytecode), manager.Options{
		DefaultKProbeMaxActive: 512,

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: 2097152 * 100,
			},
		},
		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	})
	return
}

func (d *Driver) Start() error {
	return d.Manager.Start()
}

// This is used for after-run initialization for global maps(some common values)
func (d *Driver) AfterRunInitialization() error {
	configMap, found, err := d.Manager.GetMap("config_map")
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("config_map not found")
	}
	/*
	 * enum hades_ebpf_config {
	 *	 CONFIG_HADES_PID,
	 *	 CONFIG_FILTERS
	 *};
	 */
	var syscall_index uint32 = 0
	var pid uint32 = uint32(os.Getpid())
	err = configMap.Update(syscall_index, pid, ebpf.UpdateAny)
	if err != nil {
		return err
	}
	// TODO: filters are not added for now
	return nil
}

/*
 * Close by the UID
 */
func (d *Driver) Close(UID string) (err error) {
	for _, probe := range d.Manager.Probes {
		if UID == probe.UID {
			return probe.Stop()
		}
	}
	_, err = fmt.Printf("UID %s not found", UID)
	return err
}

/*
 * Just like Close, Filter should be triggered by a task.
 * Also, just work like a yaml or other configuration.
 */

func (d *Driver) Filter() {}

func (d *Driver) dataHandler(cpu int, data []byte, perfmap *manager.PerfMap, manager *manager.Manager) {
	ctx := decoder.NewContext()
	decoder.DefaultDecoder.SetBuffer(data)
	err := decoder.DefaultDecoder.DecodeContext(ctx)
	if err != nil {
		return
	}
	defer decoder.PutContext(ctx)
	d.eventDecoder = decoder.GetEvent(ctx.Type)
	err = d.eventDecoder.Parse()
	if err != nil {
		if err == event.ErrIgnore {
			return
		}
		zap.S().Errorf("error: %s", err)
		return
	}
	ctx.SetEvent(d.eventDecoder)
	ctx.Md5 = share.GetFileHash(ctx.Exe)
	ctx.Username = share.GetUsername(strconv.Itoa(int(ctx.Uid)))
	ctx.StartTime = share.Gtime.Load().(int64)
	if data, err := ctx.MarshalJson(); err == nil {
		rawdata["data"] = data
		if Env == "debug" {
			fmt.Println(rawdata["data"])
		}
		rec := &plugin.Record{
			DataType:  1000,
			Timestamp: int64(share.Gtime.Load().(int64)),
			Data: &plugin.Payload{
				Fields: rawdata,
			},
		}
		share.Client.SendRecord(rec)
	}
}

func (d *Driver) lostHandler(CPU int, count uint64, perfMap *manager.PerfMap, manager *manager.Manager) {
	rawdata := make(map[string]string)
	rawdata["data"] = strconv.FormatUint(count, 10)
	rec := &plugin.Record{
		DataType:  999,
		Timestamp: int64(share.Gtime.Load().(int64)),
		Data: &plugin.Payload{
			Fields: rawdata,
		},
	}
	share.Client.SendRecord(rec)
}
