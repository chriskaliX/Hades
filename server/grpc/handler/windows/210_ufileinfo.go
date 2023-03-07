package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type UFileInfo struct {
	Win_User_fileinfo_filename             string `json:"win_user_fileinfo_filename"`
	Win_User_fileinfo_dwFileAttributes     string `json:"win_user_fileinfo_dwFileAttributes"`
	Win_User_fileinfo_dwFileAttributesHide string `json:"win_user_fileinfo_dwFileAttributesHide"`
	Win_User_fileinfo_md5                  string `json:"win_user_fileinfo_md5"`
	Win_User_fileinfo_m_seFileSizeof       string `json:"win_user_fileinfo_m_seFileSizeof"`
	Win_User_fileinfo_seFileAccess         string `json:"win_user_fileinfo_seFileAccess"`
	Win_User_fileinfo_seFileCreate         string `json:"win_user_fileinfo_seFileCreate"`
	Win_User_fileinfo_seFileModify         string `json:"win_user_fileinfo_seFileModify"`
}

func (k *UFileInfo) ID() int32 { return 210 }

func (k *UFileInfo) Name() string { return "user_fileinfo" }

func (c *UFileInfo) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	return json.Unmarshal([]byte(data), c)
}

func init() {
	handler.RegistEvent(&UFileInfo{})
}
