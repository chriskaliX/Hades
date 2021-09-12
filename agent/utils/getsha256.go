package utils

import (
	"agent/global"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"sync"
)

var hasherPool = sync.Pool{
	New: func() interface{} {
		return sha256.New()
	},
}

func GetSha256ByPath(path string) (shasum string, err error) {
	cacheShasum, ok := global.FileHashCache.Get(path)
	if ok {
		shasum = cacheShasum.(string)
		return
	}
	var f *os.File
	f, err = os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	fstat, err := f.Stat()
	if err != nil {
		return "", err
	}
	if fstat.Size() > 10*1024*1024 {
		return "", fmt.Errorf("File size is larger than max limitation:%v", fstat.Size())
	}
	hasher := hasherPool.Get().(hash.Hash)
	defer hasher.Reset()
	defer hasherPool.Put(hasher)
	_, err = io.Copy(hasher, f)
	if err != nil {
		return
	}
	shasum = hex.EncodeToString(hasher.Sum(nil))
	global.FileHashCache.Add(path, shasum)
	return
}
