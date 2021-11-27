package collector

// 2021-11-27 - 重写文件 hash 部分

// mtime 或者 size 变更, 则重新获取文件 hash
type FileHash struct {
	Mtime      uint64
	INode      uint64
	Size       uint32
	AccessTime uint32 // hash 获取时间
	Sha256     string
}
