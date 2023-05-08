package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type UEtwImageModinfo struct {
	Win_Etw_imageinfo_ProcessId      string `json:"win_etw_imageinfo_processId"`
	Win_Etw_imageinfo_ImageBase      string `json:"win_etw_imageinfo_imageBase"`
	Win_Etw_imageinfo_ImageSize      string `json:"win_etw_imageinfo_imageSize"`
	Win_Etw_imageinfo_SignatureLevel string `json:"win_etw_imageinfo_signatureLevel"`
	Win_Etw_imageinfo_SignatureType  string `json:"win_etw_imageinfo_signatureType"`
	Win_Etw_imageinfo_ImageChecksum  string `json:"win_etw_imageinfo_imageChecksum"`
	Win_Etw_imageinfo_TimeDateStamp  string `json:"win_etw_imageinfo_timeDateStamp"`
	Win_Etw_imageinfo_DefaultBase    string `json:"win_etw_imageinfo_defaultBase"`
	Win_Etw_imageinfo_FileName       string `json:"win_etw_imageinfo_fileName"`
	Win_Etw_imageinfo_EventName      string `json:"win_etw_imageinfo_eventname"`
}

func (k *UEtwImageModinfo) ID() int32 { return 302 }

func (k *UEtwImageModinfo) Name() string { return "user_etw_imagemodinfo" }

func (c *UEtwImageModinfo) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	return json.Unmarshal([]byte(data), c)
}

func init() {
	handler.RegistEvent(&UEtwImageModinfo{})
}
