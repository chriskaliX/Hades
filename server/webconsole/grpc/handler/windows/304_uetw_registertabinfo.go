package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type UEtwResgiterTabinfo struct {
	Win_Etw_regtab_InitialTime string `json:"win_etw_regtab_initialTime"`
	Win_Etw_regtab_Status      string `json:"win_etw_regtab_status"`
	Win_Etw_regtab_Index       string `json:"win_etw_regtab_index"`
	Win_Etw_regtab_KeyHandle   string `json:"win_etw_regtab_keyHandle"`
	Win_Etw_regtab_KeyName     string `json:"win_etw_regtab_keyName"`
	Win_Etw_regtab_EventName   string `json:"win_etw_regtab_eventname"`
}

func (k *UEtwResgiterTabinfo) ID() int32 { return 304 }

func (k *UEtwResgiterTabinfo) Name() string { return "user_etw_registertabinfo" }

func (c *UEtwResgiterTabinfo) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	return json.Unmarshal([]byte(data), c)
}

func init() {
	handler.RegistEvent(&UEtwResgiterTabinfo{})
}
