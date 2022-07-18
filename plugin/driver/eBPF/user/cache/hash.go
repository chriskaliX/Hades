package cache

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"hades-ebpf/user/share"
	"hash"
	"io"
	"os"
	"sync"
	"syscall"

	lru "github.com/hashicorp/golang-lru"
)

const freq = 60
const maxFileSize = 10485760

var DefaultHashCache = NewHashCache()

var hasherPool = &sync.Pool{
	New: func() interface{} {
		return md5.New()
	},
}

type HashCache struct {
	cache *lru.Cache
}

func NewHashCache() *HashCache {
	cache := &HashCache{}
	cache.cache, _ = lru.New(4096)
	return cache
}

func (h *HashCache) Get(path string) string {
	// get this from cache
	temp, ok := h.cache.Get(path)
	var (
		stat *syscall.Stat_t
		err  error
	)
	// if the file still in cache, check this again
	if ok {
		fileHash := temp.(*fileHash)
		// compare the accesstime
		if !fileHash.greater() {
			return fileHash.hash
		}
		fileHash.updateTime()
		// if it's less time, check the stat
		stat, err = getStat(path)
		if err != nil {
			fileHash.hash = share.INVALID_STRING
			return fileHash.hash
		}
		// file size limit
		if stat.Size > maxFileSize {
			fileHash.hash = share.INVALID_STRING
			return fileHash.hash
		}
		// if stat is invalid, get the hash and update all
		if fileHash.statInvalid(stat.Ino, stat.Mtim.Sec, stat.Size) {
			fileHash.hash = genHash(path)
			fileHash.updateStat(stat)
			return fileHash.hash
		}
		// stat is fine, just return
		return fileHash.hash
	}
	// a delay may be introduced
	fileHash := &fileHash{}
	defer h.cache.Add(path, fileHash)
	fileHash.updateTime()
	stat, err = getStat(path)
	if err != nil {
		fileHash.hash = share.INVALID_STRING
		return fileHash.hash
	}
	// file size limit
	if stat.Size > maxFileSize {
		fileHash.hash = share.INVALID_STRING
		return fileHash.hash
	}
	fileHash.hash = genHash(path)
	fileHash.updateStat(stat)
	return fileHash.hash
}

type fileHash struct {
	modtime    int64
	inode      uint64
	size       int64
	accessTime int64 // hash access time
	hash       string
}

func (fileHash *fileHash) updateTime() {
	fileHash.accessTime = share.Gtime.Load().(int64)
}

// just like osquery
func (fileHash *fileHash) greater() bool {
	if share.Gtime.Load().(int64)-fileHash.accessTime <= freq {
		return false
	}
	return true
}

func (fileHash *fileHash) statInvalid(inode uint64, mtime int64, size int64) bool {
	if fileHash.inode != inode || fileHash.modtime != mtime {
		return true
	}
	if fileHash.size != size {
		return true
	}
	return false
}

func (fileHash *fileHash) updateStat(stat *syscall.Stat_t) {
	fileHash.inode = stat.Ino
	fileHash.modtime = stat.Mtim.Sec
	fileHash.size = stat.Size
}

func getStat(path string) (*syscall.Stat_t, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		err = fmt.Errorf("%s not Stat_t", path)
		return nil, err
	}
	return stat, nil
}

func genHash(path string) (result string) {
	_file, err := os.Open(path)
	if err != nil {
		result = share.INVALID_STRING
		return
	}
	defer _file.Close()
	hash := hasherPool.Get().(hash.Hash)
	defer hasherPool.Put(hash)
	defer hash.Reset()
	if _, err = io.Copy(hash, _file); err != nil {
		result = share.INVALID_STRING
		return
	}
	result = hex.EncodeToString(hash.Sum(nil))
	return
}
