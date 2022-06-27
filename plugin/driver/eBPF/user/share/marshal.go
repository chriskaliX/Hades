package share

import (
	"hades-ebpf/user/helper"

	json "github.com/goccy/go-json"
	"go.uber.org/zap/buffer"
)

var bytepool buffer.Pool = buffer.NewPool()

// to opt
func Marshal(v interface{}) (str string, err error) {
	var buf = bytepool.Get()
	defer buf.Free()
	enc := json.NewEncoder(buf)
	enc.SetIndent("", "\t")
	enc.SetEscapeHTML(false)
	if err = enc.Encode(v); err != nil {
		return
	}
	str = helper.ZeroCopyString(buf.Bytes())
	return
}

func MarshalBytes(v interface{}) (b *buffer.Buffer, err error) {
	var buf = bytepool.Get()
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err = enc.Encode(v); err != nil {
		buf.Free()
		return
	}
	return buf, nil
}
