package support

//go:generate msgp
// RegistRequest 用来标识注册请求
type RegistRequest struct {
	Pid     uint32 `msg:"pid"`
	Name    string `msg:"name"`
	Version string `msg:"version"`
}
type Data []map[string]string

type Task struct {
	ID      uint32 `msg:"id"`
	Content string `msg:"content"`
	Token   string `msg:"token"`
}
