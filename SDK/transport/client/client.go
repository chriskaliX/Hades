package client

import (
	"bufio"
	"encoding/binary"
	fmt "fmt"
	io "io"
	"sync"

	"github.com/chriskaliX/SDK/clock"
	"github.com/chriskaliX/SDK/transport/protocol"
)

type SendHookFunction func(*protocol.Record) error

const ElkeidEnv = "SPECIFIED_AGENT_ID"

type Client struct {
	rx     io.ReadCloser
	tx     io.WriteCloser
	reader *bufio.Reader
	writer *bufio.Writer
	rmu    *sync.Mutex
	wmu    *sync.Mutex
	// Hook function for Elkeid
	hook  SendHookFunction
	clock clock.IClock
}

func (c *Client) SetSendHook(hook SendHookFunction) {
	c.hook = hook
}

func (c *Client) IsHooked() bool {
	return c.hook != nil
}

// Plugin Client send record to agent. Add an extra size flag to simplify
// the operation which agent side decodes.
// Sync With Elkeid
func (c *Client) SendElkeid(rec *protocol.Record) (err error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	size := rec.Size()
	err = binary.Write(c.writer, binary.LittleEndian, uint32(size))
	if err != nil {
		return
	}
	var buf []byte
	buf, err = rec.Marshal()
	if err != nil {
		return
	}
	_, err = c.writer.Write(buf)
	return
}

func (c *Client) SendDebug(rec *protocol.Record) (err error) {
	if _, ok := rec.Data.Fields["data"]; ok {
		fmt.Println(rec.Data.Fields["data"])
	} else {
		fmt.Println(rec.Data.Fields)
	}
	return
}

func (c *Client) SendRecord(rec *protocol.Record) (err error) {
	// fill up with the ts by ticker
	rec.Timestamp = c.clock.Now().Unix()
	// check hook
	if c.hook != nil {
		return c.hook(rec)
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	var buf []byte
	if buf, err = rec.Marshal(); err != nil {
		return
	}
	if err = binary.Write(c.writer, binary.LittleEndian, uint32(len(buf))); err != nil {
		return
	}
	_, err = c.writer.Write(buf)
	return
}

func (c *Client) ReceiveTask() (t *protocol.Task, err error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	var len uint32
	err = binary.Read(c.reader, binary.LittleEndian, &len)
	if err != nil {
		return
	}
	var buf []byte
	buf, err = c.reader.Peek(int(len))
	if err != nil {
		return
	}
	_, err = c.reader.Discard(int(len))
	if err != nil {
		return
	}
	t = &protocol.Task{}
	err = t.Unmarshal(buf)
	return
}

func (c *Client) Flush() (err error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.writer.Buffered() != 0 {
		err = c.writer.Flush()
	}
	return
}

func (c *Client) Close() {
	c.writer.Flush()
	c.rx.Close()
	c.tx.Close()
}
