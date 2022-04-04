package share

import (
	"crypto/md5"
	"encoding/hex"

	plugin "github.com/chriskaliX/plugin"
)

var Client = plugin.New()

func MD5(v string) string {
	d := []byte(v)
	m := md5.New()
	m.Write(d)
	return hex.EncodeToString(m.Sum(nil))
}
