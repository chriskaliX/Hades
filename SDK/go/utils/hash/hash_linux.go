//go:build linux

package hash

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"syscall"

	"github.com/chriskaliX/SDK/config"
)

// internal hash struct for calc
type fileHash struct {
	mtime int64
	atime int64 /* Access time for hashcache access */
	inode uint64
	size  int64
	hash  string
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
	if !h.rl.AllowN(h.clock.Now(), 1) {
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
	reader := bufio.NewReader(file)
	if _, err := reader.Read(h.buf); err != nil {
		result = config.FieldInvalid
		return
	}
	h.hash.Write([]byte(strconv.FormatInt(size, 10)))
	h.hash.Write(h.buf)
	result = fmt.Sprintf("%x", h.hash.Sum64())
	h.buf = h.buf[:0]
	h.hash.Reset()
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
