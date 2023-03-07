package utils

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"time"

	"github.com/chriskaliX/SDK/clock"
)

var Clock = clock.New(100 * time.Millisecond)

func Hash() string {
	hash := md5.New()
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(time.Now().Nanosecond()))
	hash.Write([]byte(b))
	return hex.EncodeToString(hash.Sum(nil))[:6]
}
