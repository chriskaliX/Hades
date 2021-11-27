package collector

import (
	"agent/global"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"

	lru "github.com/hashicorp/golang-lru"
)

// 2021-11-27 - 重写文件 hash 部分

// mtime 或者 size 变更, 则重新获取文件 hash
// Q: how about change
type FileHash struct {
	Mtime      int64
	Inode      uint64
	Size       int64
	AccessTime uint // hash 获取时间
	Sha256     string
}

var (
	fileHashCache *lru.ARCCache
	fileHashPool  *sync.Pool
)

const freq = 60

func GetFileHash(path string) (shasum string, err error) {
	temp, ok := fileHashCache.Get(path)
	var (
		size     int64
		modetime int64
		inode    uint64
	)
	// 文件存在
	if ok {
		fh := temp.(FileHash)
		// 对比上次 accessTime, 超过了则重新 stat
		// TODO: Time 精度
		if fh.AccessTime-global.Time > freq {
			modetime, inode, size, err = fileStat(path)
			if err != nil {
				return
			}

			if size > 10*1024*1024 {
				return "", fmt.Errorf("File size is larger than max limitation:%v", size)
			}

			// 如果 stat 和 size 相同, return
			if fh.Mtime == modetime && fh.Inode == inode {
				return fh.Sha256, nil
			} else {
				fh.AccessTime = global.Time
				fileHash, err := fileInfo(path)
				if err != nil {
					return "", err
				}
				fh.Inode = inode
				fh.Mtime = modetime
				fh.Size = size
				fh.Sha256 = fileHash.Sha256
				fileHashCache.Add(path, fh)
				return fileHash.Sha256, nil
			}
		}
		return fh.Sha256, nil
	}

	modetime, inode, size, err = fileStat(path)
	if err != nil {
		return
	}
	if size > 10*1024*1024 {
		return "", fmt.Errorf("File size is larger than max limitation:%v", size)
	}
	fh, err := fileInfo(path)
	if err != nil {
		return
	}
	fh.AccessTime = global.Time
	fh.Mtime = modetime
	fh.Inode = inode
	fh.Size = size
	fileHashCache.Add(path, fh)
	return fh.Sha256, nil
}

func fileStat(path string) (modetime int64, inode uint64, size int64, err error) {
	finfo, err := os.Stat(path)
	if err != nil {
		return
	}
	stat, ok := finfo.Sys().(*syscall.Stat_t)
	if !ok {
		err = fmt.Errorf("%s not Stat_t", path)
		return
	}
	return finfo.ModTime().Unix(), stat.Ino, finfo.Size(), nil
}

func fileInfo(path string) (FileHash, error) {
	fh := FileHash{}
	var f *os.File
	f, err := os.Open(path)
	if err != nil {
		return fh, err
	}
	defer f.Close()
	hash := sha256.New()
	_, err = io.Copy(hash, f)
	if err != nil {
		return fh, err
	}
	shasum := hex.EncodeToString(hash.Sum(nil))
	fh.Sha256 = shasum
	return fh, nil
}

func init() {
	fileHashCache, _ = lru.NewARC(2048)
	fileHashPool = &sync.Pool{
		New: func() interface{} {
			return new(FileHash)
		},
	}
}
