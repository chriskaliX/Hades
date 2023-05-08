package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type UDriectInfo struct {
	Win_User_driectinfo_flag     string `json:"win_user_driectinfo_flag"`
	Win_User_driectinfo_filecout string `json:"win_user_driectinfo_filecout"`
	Win_User_driectinfo_size     string `json:"win_user_driectinfo_size"`
	Win_User_driectinfo_filename string `json:"win_user_driectinfo_filename"`
	Win_User_driectinfo_filePath string `json:"win_user_driectinfo_filePath"`
	Win_User_driectinfo_fileSize string `json:"win_user_driectinfo_fileSize"`
}

func (k *UDriectInfo) ID() int32 { return 209 }

func (k *UDriectInfo) Name() string { return "user_direct_info" }

func (c *UDriectInfo) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	return json.Unmarshal([]byte(data), c)
}

func init() {
	handler.RegistEvent(&UDriectInfo{})
}
