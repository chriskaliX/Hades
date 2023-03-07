package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type UEtwThreadinfo struct {
	Win_Etw_threadinfo_pid            string `json:"win_etw_threadinfo_pid"`
	Win_Etw_threadinfo_tid            string `json:"win_etw_threadinfo_tid"`
	Win_Etw_threadinfo_Win32StartAddr string `json:"win_etw_threadinfo_win32startaddr"`
	Win_Etw_threadinfo_ThreadFlags    string `json:"win_etw_threadinfo_flags"`
	Win_Etw_threadinfo_EventName      string `json:"win_etw_threadinfo_eventname"`
}

func (k *UEtwThreadinfo) ID() int32 { return 301 }

func (k *UEtwThreadinfo) Name() string { return "user_etw_threadinfo" }

func (c *UEtwThreadinfo) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	return json.Unmarshal([]byte(data), c)
}

func init() {
	handler.RegistEvent(&UEtwThreadinfo{})
}
