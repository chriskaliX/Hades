package utils

import (
	"bytes"
	"encoding/json"
)

// golang, json marshal 的时候会对 html unicode, 需要自己定义 encoder
func Marshal(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(v)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
