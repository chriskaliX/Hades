package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type KRootkitNetWork struct {
	Win_Rootkit_Net_mod               string `json:"win_rootkit_is_mod"`
	Win_Rootkit_Net_tcp_pid           string `json:"win_rootkit_tcp_pid"`
	Win_Rootkit_Net_tcp_localIp_port  string `json:"win_rootkit_tcp_localIp_port"`
	Win_Rootkit_Net_tcp_remoteIp_port string `json:"win_rootkit_tcp_remoteIp_port"`
	Win_Rootkit_Net_tcp_Status        string `json:"win_rootkit_tcp_Status"`
	Win_Rootkit_Net_udp_pid           string `json:"win_rootkit_udp_pid"`
	Win_Rootkit_Net_udp_localIp_port  string `json:"win_rootkit_udp_localIp_port"`
}

func (k *KRootkitNetWork) ID() int32 { return 110 }

func (k *KRootkitNetWork) Name() string { return "kernel_rootkit_network" }

func (c *KRootkitNetWork) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	return json.Unmarshal([]byte(data), c)
}

func init() {
	handler.RegistEvent(&KRootkitNetWork{})
}
