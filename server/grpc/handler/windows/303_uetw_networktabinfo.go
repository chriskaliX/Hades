package windows

import (
	"encoding/json"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type UEtwNetWorkTabinfo struct {
	Win_Etw_network_addressFamily   string `json:"win_network_addressfamily"`
	Win_Etw_network_LocalAddr       string `json:"win_network_localaddr"`
	Win_Etw_network_toLocalPort     string `json:"win_network_toLocalport"`
	Win_Etw_network_protocol        string `json:"win_network_protocol"`
	Win_Etw_network_RemoteAddr      string `json:"win_network_remoteaddr"`
	Win_Etw_network_toRemotePort    string `json:"win_network_toremoteport"`
	Win_Etw_network_processPath     string `json:"win_network_procespath"`
	Win_Etw_network_processPathSize string `json:"win_network_processpathsize"`
	Win_Etw_network_processId       string `json:"win_network_processid"`
	Win_Etw_network_eventName       string `json:"win_network_eventname"`
}

func (k *UEtwNetWorkTabinfo) ID() int32 { return 303 }

func (k *UEtwNetWorkTabinfo) Name() string { return "user_etw_networktabinfo" }

func (c *UEtwNetWorkTabinfo) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	return json.Unmarshal([]byte(data), c)
}
