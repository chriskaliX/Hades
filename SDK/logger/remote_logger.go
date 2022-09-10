package logger

import (
	"strconv"

	json "github.com/bytedance/sonic"

	"github.com/chriskaliX/SDK/clock"
	"github.com/chriskaliX/SDK/config"
	"github.com/chriskaliX/SDK/transport/client"
	"github.com/chriskaliX/SDK/transport/protocol"
)

type remoteWriter struct {
	client *client.Client
	clock  clock.IClock
}

func (w *remoteWriter) Write(p []byte) (n int, err error) {
	if w.client == nil {
		return
	}
	rec := &protocol.Record{
		DataType:  config.TypePluginError,
		Timestamp: w.clock.Now().Unix(),
		Data: &protocol.Payload{
			Fields: map[string]string{},
		},
	}
	fields := map[string]interface{}{}
	err = json.Unmarshal(p, &fields)
	if err != nil {
		return
	}
	for k, v := range fields {
		switch v := v.(type) {
		case string:
			rec.Data.Fields[k] = v
		case int:
			rec.Data.Fields[k] = strconv.Itoa(v)
		}
	}
	if err = w.client.SendRecord(rec); err != nil {
		return
	}
	n = len(p)
	return
}

func (w *remoteWriter) Sync() error {
	if w.client != nil {
		return w.client.Flush()
	} else {
		return nil
	}
}
