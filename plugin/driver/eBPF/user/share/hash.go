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
type FileHash struct {
	modtime    int64
	inode      uint64
	size       int64
	accessTime int64 // hash access time
	Hash       string
}

var (
	fileHashCache, _ = lru.NewARC(2048)
	fileHashPool     = &sync.Pool{
		New: func() interface{} {
			return new(FileHash)
		},
	}
	hasherPool = &sync.Pool{
		New: func() interface{} {
			return md5.New()
		},
	}
)

const freq = 60
const maxFileSize = 10485760

func GetFileHash(path string) (shasum string, err error) {
	temp, ok := fileHashCache.Get(path)
	var (
		size    int64
		modtime int64
		inode   uint64
	)
	if ok {
		fh := temp.(FileHash)
		// compare the accesstime
		if Gtime.Load().(int64)-fh.accessTime <= freq {
			return fh.Hash, nil
		}
		modtime, inode, size, err = fileStat(path)
		if err != nil {
			return
		}

		if size > maxFileSize {
			return "", fmt.Errorf("File size is larger than max limitation:%v", size)
		}

		// 如果 stat 和 size 相同, return
		if fh.modtime == modtime && fh.inode == inode {
			return fh.Hash, nil
		}
		fileHash, err := fileInfo(path)
		if err != nil {
			return "", err
		}
		fh.inode = inode
		fh.modtime = modtime
		fh.size = size
		fh.Hash = fileHash.Hash
		fileHashCache.Add(path, fh)
		return fileHash.Hash, nil
	}

	modtime, inode, size, err = fileStat(path)
	if err != nil {
		return
	}
	if size > maxFileSize {
		return "", fmt.Errorf("File size is larger than max limitation:%v", size)
	}
	fh, err := fileInfo(path)
	if err != nil {
		return
	}
	fh.accessTime = Gtime.Load().(int64)
	fh.modtime = modtime
	fh.inode = inode
	fh.size = size
	fileHashCache.Add(path, fh)
	return fh.Hash, nil
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
	fh.Hash = shasum
	return fh, nil
}
