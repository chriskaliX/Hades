package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type KRootkitFsd struct {
	Win_Rootkit_Fsd_fsdmod            string `json:"win_rootkit_is_fsdmod"`
	Win_Rootkit_Fsd_fsdfastfat_id     string `json:"win_rootkit_fsdfastfat_id"`
	Win_Rootkit_Fsd_fsdfastfat_mjaddr string `json:"win_rootkit_fsdfastfat_mjaddr"`
	Win_Rootkit_Fsd_fsdntfs_id        string `json:"win_rootkit_fsdntfs_id"`
	Win_Rootkit_Fsd_fsdntfs_mjaddr    string `json:"win_rootkit_fsdntfs_mjaddr"`
}

func (k *KRootkitFsd) ID() int32 { return 108 }

func (k *KRootkitFsd) Name() string { return "kernel_rootkit_fsd" }

func (c *KRootkitFsd) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	return json.Unmarshal([]byte(data), c)
}

func init() {
	handler.RegistEvent(&KRootkitFsd{})
}
