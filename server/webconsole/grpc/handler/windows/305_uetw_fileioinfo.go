package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type UEtwFileIoInfo struct {
	Win_Etw_fileio_EventName      string `json:"win_etw_fileio_eventname"`
	Win_Etw_fileio_FilePath       string `json:"win_etw_fileio_FilePath"`
	Win_Etw_fileio_FileName       string `json:"win_etw_fileio_FileName"`
	Win_Etw_fileio_Tid            string `json:"win_etw_fileio_Tid"`
	Win_Etw_fileio_FileAttributes string `json:"win_etw_fileio_FileAttributes"`
	Win_Etw_fileio_CreateOptions  string `json:"win_etw_fileio_CreateOptions"`
	Win_Etw_fileio_ShareAccess    string `json:"win_etw_fileio_ShareAccess"`
	Win_Etw_fileio_Offset         string `json:"win_etw_fileio_Offset"`
	Win_Etw_fileio_FileKey        string `json:"win_etw_fileio_FileKey"`
	Win_Etw_fileio_FileObject     string `json:"win_etw_fileio_FileObject"`
}

func (k *UEtwFileIoInfo) ID() int32 { return 305 }

func (k *UEtwFileIoInfo) Name() string { return "user_etw_fileioinfo" }

func (c *UEtwFileIoInfo) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	return json.Unmarshal([]byte(data), c)
}

func init() {
	handler.RegistEvent(&UEtwFileIoInfo{})
}
