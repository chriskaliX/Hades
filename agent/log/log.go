package log

import (
	"agent/global"
	"encoding/json"
	"fmt"
)

type ErrorLog struct {
	Level     string `json:"level"`
	Timestamp string `json:"timestamp"`
	Source    string `json:"source"`
	Msg       string `json:"msg"`
}

type LoggerWriter struct{}

func (*LoggerWriter) Write(p []byte) (n int, err error) {
	l := ErrorLog{}
	e := json.Unmarshal(p, &l)
	if err != nil {
		return 0, e
	}
	m := make(map[string]string)
	m["level"] = l.Level
	m["timestamp"] = l.Timestamp
	m["source"] = l.Source
	m["msg"] = l.Msg
	m["data_type"] = "999"
	select {
	case global.UploadChannel <- m:
	default:
		fmt.Println("Channel full")
	}
	return len(p), nil
}
