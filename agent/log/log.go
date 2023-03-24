package log

import (
	"agent/proto"
	"agent/transport"
	"encoding/json"
	"strconv"
	"time"
)

type GrpcWriter struct{}

func (w *GrpcWriter) Write(p []byte) (n int, err error) {
	rec := &proto.Record{
		Timestamp: time.Now().Unix(),
		DataType:  1010,
		Data: &proto.Payload{
			Fields: map[string]string{},
		},
	}
	fields := map[string]any{}
	err = json.Unmarshal(p, &fields)
	if err != nil {
		return
	}
	timestamp, ok := fields["timestamp"]
	if ok {
		timestamp, err := strconv.ParseInt(timestamp.(string), 10, 64)
		if err == nil {
			rec.Timestamp = timestamp
			delete(fields, "timestamp")
		}
	}
	if rec.Timestamp == 0 {
		rec.Timestamp = time.Now().Unix()
	}
	for k, v := range fields {
		switch v := v.(type) {
		case string:
			rec.Data.Fields[k] = v
		case int:
			rec.Data.Fields[k] = strconv.Itoa(v)
		}
	}
	if err = transport.Trans.Transmission(rec, false); err != nil {
		return
	}
	n = len(p)
	return
}

func (w *GrpcWriter) Sync() error {
	return nil
}
