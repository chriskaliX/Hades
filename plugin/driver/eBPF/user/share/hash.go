package share

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"sync"
	"syscall"

	lru "github.com/hashicorp/golang-lru"
)

/*
 *: FileHashCache 应该要定时淘汰, 例如我给 /usr/bin/ps 加白, 但是文件被替换
 * Source Code of OSQuery:
 * https://github.com/osquery/osquery/blob/a540d73cbb687aa36e7562b7dcca0cd0e567ca6d/osquery/tables/system/hash.cpp
 * @brief Checks the current stat output against the cached view.
 *
 * If the modified/altered time or the file's inode has changed then the hash
 * should be recalculated.
 *
 * Syscall here should be improved
 */

var (
	fileHashCache, _ = lru.NewARC(2048)
	hasherPool       = &sync.Pool{
		New: func() interface{} {
			return md5.New()
		},
	}
)

const freq = 60
const maxFileSize = 10485760

type FileHash struct {
	modtime    int64
	inode      uint64
	size       int64
	accessTime int64 // hash access time
	hash       string
}

func (fileHash *FileHash) updateTime() {
	fileHash.accessTime = Gtime.Load().(int64)
}

// just like osquery
func (fileHash *FileHash) greater() bool {
	if Gtime.Load().(int64)-fileHash.accessTime <= freq {
		return false
	}
	return true
}

func (fileHash *FileHash) statInvalid(inode uint64, mtime int64, size int64) bool {
	if fileHash.inode != inode || fileHash.modtime != mtime {
		return true
	}
	if fileHash.size != size {
		return true
	}
	return false
}

func (fileHash *FileHash) updateStat(stat *syscall.Stat_t) {
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
		result = INVALID_STRING
		return
	}
	defer _file.Close()
	hash := hasherPool.Get().(hash.Hash)
	defer hasherPool.Put(hash)
	defer hash.Reset()
	if _, err = io.Copy(hash, _file); err != nil {
		result = INVALID_STRING
		return
	}
	result = hex.EncodeToString(hash.Sum(nil))
	return
}

func GetFileHash(path string) string {
	// get this from cache
	temp, ok := fileHashCache.Get(path)
	var (
		stat *syscall.Stat_t
		err  error
	)
	// if the file still in cache, check this again
	if ok {
		fileHash := temp.(*FileHash)
		// compare the accesstime
		if !fileHash.greater() {
			return fileHash.hash
		}
		fileHash.updateTime()
		// if it's not in cache, check the stat
		stat, err = getStat(path)
		if err != nil {
			fileHash.hash = INVALID_STRING
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
	fileHash := &FileHash{}
	defer fileHashCache.Add(path, fileHash)
	fileHash.updateTime()
	stat, err = getStat(path)
	if err != nil {
		fileHash.hash = INVALID_STRING
		return fileHash.hash
	}
	fileHash.hash = genHash(path)
	fileHash.updateStat(stat)
	return fileHash.hash
}
