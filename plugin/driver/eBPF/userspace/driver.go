package userspace

import (
	"bytes"
	_ "embed"
	"fmt"
	"hades-ebpf/userspace/decoder"
	"hades-ebpf/userspace/helper"
	"hades-ebpf/userspace/share"
	"math"
	"os"
	"strconv"

	"github.com/chriskaliX/plugin"
	"github.com/cilium/ebpf"
	manager "github.com/ehids/ebpfmanager"
	"golang.org/x/sys/unix"
)

const debug = true

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
	for _, event := range events {
		d.Manager.Probes = append(d.Manager.Probes, event.GetProbe())
	}
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
	err = d.Manager.InitWithOptions(bytes.NewReader(_bytecode), manager.Options{
		DefaultKProbeMaxActive: 512,

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: 2097152,
			},
		},

		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	})
	return
}

func (d *Driver) Run() error {
	return d.Manager.Start()
}

func (d *Driver) dataHandler(cpu int, data []byte, perfmap *manager.PerfMap, manager *manager.Manager) {
	decoder.DefaultDecoder.SetBuffer(data)
	ctx, err := decoder.DefaultDecoder.DecodeContext()
	if err != nil {
		decoder.PutContext(ctx)
		return
	}
	d.eventDecoder = decoder.GetEvent(ctx.Type)
	d.eventDecoder.Parse()
	ctx.SetEvent(d.eventDecoder)
	ctx.Sha256, _ = share.GetFileHash(ctx.Exe)
	ctx.Username = share.GetUsername(strconv.Itoa(int(ctx.Uid)))
	ctx.StartTime = uint64(share.Time)
	if data, err := share.Marshal(ctx); err == nil {
		rawdata["data"] = helper.ZeroCopyString(data)
		if debug {
			fmt.Println(rawdata)
		}
		rec := &plugin.Record{
			DataType:  1000,
			Timestamp: int64(share.Time),
			Data: &plugin.Payload{
				Fields: rawdata,
			},
		}
		share.Client.SendRecord(rec)
	}
	decoder.PutContext(ctx)
}

func (d *Driver) lostHandler(CPU int, count uint64, perfMap *manager.PerfMap, manager *manager.Manager) {
	fmt.Println(count)
}
