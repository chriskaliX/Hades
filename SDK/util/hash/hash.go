package hash

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/chriskaliX/SDK/clock"
	"github.com/chriskaliX/SDK/config"
	"golang.org/x/time/rate"
	"k8s.io/utils/lru"
)

const (
	freq          = 60
	maxFileSize   = 10485760
	hashCacheSize = 4096
	burst         = 32
)

type IHashCache interface {
	GetHash(path string) string
}

type HashCache struct {
	cache *lru.Cache
	pool  *sync.Pool
	clock clock.IClock
	rl    *rate.Limiter
}

// internal hash struct for calc
type fileHash struct {
	mtime int64
	atime int64 /* Access time for hashcache access */
	inode uint64
	size  int64
	hash  string
}

func NewWithClock(c clock.IClock) *HashCache {
	return &HashCache{
		cache: lru.New(hashCacheSize),
		pool: &sync.Pool{
			New: func() interface{} {
				return md5.New()
			},
		},
		clock: c,
		rl:    rate.NewLimiter(rate.Every(5*time.Microsecond), burst),
	}
}

// GetHash returns the hash of the hash
//
// Firstly, we get from the lru cache, and check the access
// time for every access. Hash would be re-calculated if the
// atime is over 60.
// Also, any calculation action will be limited for better
// performance
func (h *HashCache) GetHash(path string) (hash string) {
	var now = h.clock.Now().Unix()
	_hash, ok := h.cache.Get(path)
	if ok {
		fileHash := _hash.(*fileHash)
		if now-fileHash.atime <= freq {
			return fileHash.hash
		}
		// Action will be done, update access time firstly
		fileHash.atime = now
		return h.getHash(path, fileHash)
	}
	f := &fileHash{}
	defer h.cache.Add(path, f)
	f.atime = now
	return h.getHash(path, f)
}

func (h *HashCache) getHash(path string, f *fileHash) string {
	if !h.rl.Allow() {
		return config.FieldOverrate
	}

	var (
		stat *syscall.Stat_t
		err  error
	)
	if stat, err = h.getStat(path); err != nil {
		f.hash = config.FieldInvalid
		return f.hash
	}
	if stat.Size > maxFileSize {
		f.hash = config.FieldOversize
		return f.hash
	}
	if f.check(stat) {
		f.hash = h.genHash(path, stat.Size)
		f.update(stat)
		return f.hash
	}
	return f.hash
}

func (h *HashCache) getStat(path string) (*syscall.Stat_t, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		err = fmt.Errorf("%s not Stat_t", path)
		return nil, err
	}
	return stat, nil
}

func (h *HashCache) genHash(path string, size int64) (result string) {
	file, err := os.Open(path)
	if err != nil {
		result = config.FieldInvalid
		return
	}
	defer file.Close()
	hash := h.pool.Get().(hash.Hash)
	defer h.pool.Put(hash)
	defer hash.Reset()
	// use CopyN for potential TOUTOC problem
	if _, err = io.CopyN(hash, file, size); err != nil {
		result = config.FieldInvalid
		return
	}
	result = hex.EncodeToString(hash.Sum(nil))
	return
}

func (f *fileHash) check(stat *syscall.Stat_t) bool {
	return f.inode != stat.Ino || f.mtime != stat.Mtim.Sec || f.size != stat.Size
}

func (f *fileHash) update(stat *syscall.Stat_t) {
	f.inode = stat.Ino
	f.mtime = stat.Mtim.Sec
	f.size = stat.Size
}
