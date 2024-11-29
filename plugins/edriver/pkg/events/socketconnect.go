package event

import (
	"edriver/constants"
	"edriver/pkg/decoder"
	"edriver/utils"
	"fmt"
	"time"

	manager "github.com/gojue/ebpfmanager"
	utilcache "k8s.io/apimachinery/pkg/util/cache"
)

// Socket connect should be enforced with a filter.
//
// Also, the filter can be impletemented in kernel space since
// the lru & map is easy in BPF. But for now, we just introduce
// the map into userspace for filter usage.
var _ decoder.Event = (*SysConnect)(nil)

var connection_ttl_cache = utilcache.NewLRUExpireCacheWithClock(1024*8, utils.Clock)

type SysConnect struct {
	Family uint16 `json:"family"`
	Dport  uint16 `json:"dport"`
	Dip    string `json:"dip"`
	Sport  uint16 `json:"sport"`
	Sip    string `json:"sip"`
	Exe    string `json:"-"`
}

func (SysConnect) ID() uint32 {
	return 1022
}

func (SysConnect) Name() string {
	return "sys_connect"
}

func (s *SysConnect) GetExe() string {
	return s.Exe
}

func (s *SysConnect) DecodeEvent(d *decoder.EbpfDecoder) (err error) {
	if s.Family, s.Sport, s.Dport, s.Sip, s.Dip, err = d.DecodeAddr(); err != nil {
		return
	}
	key := fmt.Sprintf("%s%s%d", s.Sip, s.Dip, s.Dport)
	// only works in not Debug
	if !constants.Debug {
		if _, ok := connection_ttl_cache.Get(key); ok {
			return decoder.ErrIgnore
		} else {
			connection_ttl_cache.Add(key, true, 30*time.Minute)
		}
	}
	s.Exe, err = d.DecodeString()
	return
}

func (SysConnect) GetProbes() []*manager.Probe {
	return []*manager.Probe{
		{
			UID:              "tracepoint_sys_enter_connect",
			Section:          "tracepoint/syscalls/sys_enter_connect",
			EbpfFuncName:     "sys_enter_connect",
			AttachToFuncName: "sys_enter_connect",
		},
		{
			UID:              "tracepoint_sys_exit_connect",
			Section:          "tracepoint/syscalls/sys_exit_connect",
			EbpfFuncName:     "sys_exit_connect",
			AttachToFuncName: "sys_exit_connect",
		},
	}
}

func (s *SysConnect) GetMaps() []*manager.Map { return nil }

func (SysConnect) RegistCron() (string, decoder.EventCronFunc) { return "", nil }

func init() { decoder.RegistEvent(&SysConnect{}) }
