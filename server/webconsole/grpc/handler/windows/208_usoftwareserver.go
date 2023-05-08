package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type USoftwareServer struct {
	Win_User_softwareserver_flag    string `json:"win_user_softwareserver_flag"`
	Win_User_server_lpsName         string `json:"win_user_server_lpsName"`
	Win_User_server_lpdName         string `json:"win_user_server_lpdName"`
	Win_User_server_lpPath          string `json:"win_user_server_lpPath"`
	Win_User_server_lpDescr         string `json:"win_user_server_lpDescr"`
	Win_User_server_status          string `json:"win_user_server_status"`
	Win_User_software_lpsName       string `json:"win_user_software_lpsName"`
	Win_User_software_Size          string `json:"win_user_software_Size"`
	Win_User_software_Ver           string `json:"win_user_software_Ver"`
	Win_User_software_installpath   string `json:"win_user_software_installpath"`
	Win_User_software_uninstallpath string `json:"win_user_software_uninstallpath"`
	Win_User_software_data          string `json:"win_user_software_data"`
	Win_User_software_venrel        string `json:"win_user_software_venrel"`
}

func (k *USoftwareServer) ID() int32 { return 208 }

func (k *USoftwareServer) Name() string { return "user_software_server" }

func (c *USoftwareServer) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	return json.Unmarshal([]byte(data), c)
}

func init() {
	handler.RegistEvent(&USoftwareServer{})
}
