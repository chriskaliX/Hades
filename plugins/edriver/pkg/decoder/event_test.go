package decoder

import (
	"testing"

	manager "github.com/gojue/ebpfmanager"
	"github.com/stretchr/testify/assert"
)

var _ Event = (*TEvent)(nil)

type TEvent struct {
	Field string `json:"field"`
}

func (e *TEvent) ID() uint32 { return 1 }

func (e *TEvent) Name() string { return "tevent" }

func (e *TEvent) GetExe() string { return "" }

func (e *TEvent) DecodeEvent(*EbpfDecoder) error { return nil }

func (e *TEvent) GetProbes() []*manager.Probe { return nil }

func (e *TEvent) GetMaps() []*manager.Map { return nil }

func (e *TEvent) RegistCron() (string, EventCronFunc) { return "", nil }

func TestEvent(t *testing.T) {
	RegistEvent(&TEvent{})
	SetAllowList([]string{})
	if len(Events) != 1 {
		t.Fatal("events maybe unexpectly filter")
	}
	SetAllowList([]string{"2"})
	if len(Events) != 0 {
		t.Fatal("SetAllowList not working")
	}
}

func TestMarshalJson(t *testing.T) {
	// without context
	event := TEvent{
		Field: "i am field",
	}
	res, err := MarshalJson(&event, nil)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, res, `{"field":"i am field"}`)
	// with context
	res, err = MarshalJson(&event, &Context{
		StartTime: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, res, `{"starttime":1000,"cgroupid":0,"pns":0,"pid":0,"tid":0,"uid":0,"gid":0,"ppid":0,"pgid":0,"sessionid":0,"comm":"","pcomm":"","nodename":"","retval":0,"exe_hash":"","username":"","exe":"","syscall":"","ppid_argv":"","pgid_argv":"","pod_name":"","field":"i am field"}`)
}
