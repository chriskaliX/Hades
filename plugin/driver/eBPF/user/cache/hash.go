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

	"k8s.io/utils/lru"
)

const (
	freq          = 60
	maxFileSize   = 10485760
	hashCacheSize = 4096
)

var hasherPool = &sync.Pool{
	New: func() interface{} {
		return md5.New()
	},
}

var DefaultHashCache = NewHashCache()

type HashCache struct {
	cache *lru.Cache
}

// internal hash struct for calc
type fileHash struct {
	modtime int64
	inode   uint64
	size    int64
	// access time is the last time the file stat is accessed
	accessTime int64
	hash       string
}

func NewHashCache() *HashCache {
	return &HashCache{
		cache: lru.New(hashCacheSize),
	}
}

func (h *HashCache) Get(path string) string {
	// get this from cache
	_hash, ok := h.cache.Get(path)
	var (
		stat *syscall.Stat_t
		err  error
	)
	// if the file still in cache, check this again
	if ok {
		fileHash := _hash.(*fileHash)
		// compare the access time, if the access time
		// is less than freq, the hash remains valiable
		if !fileHash.greater() {
			return fileHash.hash
		}
		// update access time
		fileHash.updateAccessTime()
		// restat the path
		// And recheck the file size and the stat
		stat, err = getStat(path)
		if err != nil {
			fileHash.hash = InVaild
			return fileHash.hash
		}
		if stat.Size > maxFileSize {
			fileHash.hash = InVaild
			return fileHash.hash
		}
		// if stat is invalid, get the hash and update new stat
		if fileHash.statInvalid(stat.Ino, stat.Mtim.Sec, stat.Size) {
			fileHash.hash = genHash(path)
			fileHash.updateStat(stat)
			return fileHash.hash
		}
		// stat is fine, just return
		return fileHash.hash
	}
	// the path is not in the cache
	fileHash := &fileHash{}
	defer h.cache.Add(path, fileHash)
	fileHash.updateAccessTime()
	stat, err = getStat(path)
	if err != nil {
		fileHash.hash = InVaild
		return fileHash.hash
	}
	// file size limitation for better performance
	if stat.Size > maxFileSize {
		fileHash.hash = InVaild
		return fileHash.hash
	}
	fileHash.hash = genHash(path)
	fileHash.updateStat(stat)
	return fileHash.hash
}

func (fileHash *fileHash) updateAccessTime() {
	fileHash.accessTime = share.Gtime.Load().(int64)
}

// compare the access time
func (fileHash *fileHash) greater() bool {
	if share.Gtime.Load().(int64)-fileHash.accessTime <= freq {
		return false
	}
	return true
}

// compare the stat from the cache
func (fileHash *fileHash) statInvalid(inode uint64, mtime int64, size int64) bool {
	return fileHash.inode != inode || fileHash.modtime != mtime || fileHash.size != size
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
		result = InVaild
		return
	}
	defer _file.Close()
	hash := hasherPool.Get().(hash.Hash)
	defer hasherPool.Put(hash)
	defer hash.Reset()
	if _, err = io.Copy(hash, _file); err != nil {
		result = InVaild
		return
	}
	result = hex.EncodeToString(hash.Sum(nil))
	return
}
