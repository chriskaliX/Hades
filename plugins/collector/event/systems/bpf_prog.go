package systems

import (
	"collector/eventmanager"
	"collector/utils"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/cilium/ebpf"
	"k8s.io/apimachinery/pkg/util/version"
)

var bpfInterval = 50 * time.Millisecond
var bpfMinKV, _ = version.ParseGeneric("4.13.0")

type BPFProg struct {
	version *version.Version
}

func (BPFProg) DataType() int { return 3014 }

func (BPFProg) Name() string { return "bpf_prog" }

func (BPFProg) Flag() eventmanager.EventMode { return eventmanager.Periodic }

func (BPFProg) Immediately() bool { return false }

func (b *BPFProg) Run(s SDK.ISandbox, sig chan struct{}) (err error) {
	if b.version == nil {
		b.version, err = version.ParseGeneric(utils.KernelVersion)
		if err != nil {
			return
		}
	}
	if b.version.LessThan(bpfMinKV) {
		return nil
	}
	hash := utils.Hash()
	// Pre-check kernel version
	last := ebpf.ProgramID(0)
	for {
		next, err := ebpf.ProgramGetNextID(last)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return err
		}
		if next <= last {
			return fmt.Errorf("last %d, next %d", last, next)
		}
		last = next
		time.Sleep(bpfInterval)
		// report here
		prog, err := ebpf.NewProgramFromID(next)
		if err != nil {
			continue
		}
		info, err := prog.Info()
		if err != nil {
			continue
		}
		runCount, _ := info.RunCount()
		runTime, _ := info.Runtime()
		var pinned string = "false"
		if prog.IsPinned() {
			pinned = "true"
		}
		rec := &protocol.Record{
			DataType:  int32(b.DataType()),
			Timestamp: utils.Clock.Now().Unix(),
			Data: &protocol.Payload{
				Fields: map[string]string{
					"id":          strconv.Itoa(int(next)),
					"fd":          strconv.Itoa(prog.FD()),
					"name":        info.Name,
					"type":        strings.ToLower(info.Type.String()),
					"tag":         info.Tag,
					"run_count":   strconv.FormatUint(runCount, 10),
					"run_time":    strconv.FormatFloat(runTime.Seconds(), 'f', 2, 64),
					"pinned":      pinned,
					"package_seq": hash,
				},
			},
		}
		s.SendRecord(rec)
	}
	return
}

func init() { addEvent(&BPFProg{}, 24*time.Hour) }
