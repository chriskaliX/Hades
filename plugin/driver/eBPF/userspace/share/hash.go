package share

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"sync"
	"syscall"

	lru "github.com/hashicorp/golang-lru"
)

// 2021-11-27 - 重写文件 hash 部分

/*
TODO: FileHashCache 应该要定时淘汰, 例如我给 /usr/bin/ps 加白, 但是文件被替换
TODO: osquery 支持多种 hash, 看是否有必要

TODO: 其他的 id 同理, 看一下是否有问题
osquery 的处理方法在源码 https://github.com/osquery/osquery/blob/a540d73cbb687aa36e7562b7dcca0cd0e567ca6d/osquery/tables/system/hash.cpp
里面有一句注释是:
 * @brief Checks the current stat output against the cached view.
 *
 * If the modified/altered time or the file's inode has changed then the hash
 * should be recalculated.
我看了一下 osquery 的代码, 每次来 get 的时候, 都会去 stat 0x200 长度
还有一个 ssdeep
TODO: ssdeep
*/

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
	hasherPool    *sync.Pool
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
		if fh.AccessTime-Time > freq {
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
				// fh.AccessTime = Time
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
	fh.AccessTime = Time
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
	hash := hasherPool.Get().(hash.Hash)
	defer hasherPool.Put(hash)
	defer hash.Reset()
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

	hasherPool = &sync.Pool{
		New: func() interface{} {
			return sha256.New()
		},
	}
}
