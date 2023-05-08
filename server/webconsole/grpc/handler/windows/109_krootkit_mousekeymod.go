package windows

import (
	"encoding/json"
	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
)

type KRootkitMouseKeyMod struct {
	Win_Rootkit_MouseKey_Mousekey_mod string `json:"win_rootkit_is_mousekeymod"`
	Win_Rootkit_MouseKey_Mouse_id     string `json:"win_rootkit_Mouse_id"`
	Win_Rootkit_MouseKey_Mouse_mjaddr string `json:"win_rootkit_Mouse_mjaddr"`
	Win_Rootkit_MouseKey_i8042_id     string `json:"win_rootkit_i8042_id"`
	Win_Rootkit_MouseKey_i8042_mjaddr string `json:"win_rootkit_i8042_mjaddr"`
	Win_Rootkit_MouseKey_kbd_id       string `json:"win_rootkit_kbd_id"`
	Win_Rootkit_MouseKey_kbd_mjaddr   string `json:"win_rootkit_kbd_mjaddr"`
}

func (k *KRootkitMouseKeyMod) ID() int32 { return 109 }

func (k *KRootkitMouseKeyMod) Name() string { return "kernel_rootkit_mousekey_mod" }

func (c *KRootkitMouseKeyMod) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	data := m["udata"]
	return json.Unmarshal([]byte(data), c)
}

func init() {
	handler.RegistEvent(&KRootkitMouseKeyMod{})
}
