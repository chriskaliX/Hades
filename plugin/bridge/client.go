package plugin

import (
	"bufio"
	"encoding/binary"
	io "io"
	"sync"
)

type Client struct {
	rx     io.ReadCloser
	tx     io.WriteCloser
	reader *bufio.Reader
	writer *bufio.Writer
	rmu    *sync.Mutex
	wmu    *sync.Mutex
}

// Plugin Client send record to agent. Add an extra size flag to simplify
// the operation which agent side decodes.
func (c *Client) SendRecord(rec *Record) (err error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	var buf []byte
	size := rec.Size()
	if err = binary.Write(c.writer, binary.LittleEndian, uint32(size)); err != nil {
		return
	}
	if buf, err = rec.Marshal(); err != nil {
		return
	}
	_, err = c.writer.Write(buf)
	return
}

func (c *Client) SendRecordWithSize(rec *Record) (err error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	var buf []byte
	size := rec.Size()
	if err = binary.Write(c.writer, binary.LittleEndian, uint32(size)); err != nil {
		return
	}
	if buf, err = rec.Marshal(); err != nil {
		return
	}
	// TODO: move to a sync.Pool
	sizebuf := make([]byte, 4)
	binary.BigEndian.PutUint32(sizebuf, uint32(size))
	if _, err = c.writer.Write(sizebuf); err != nil {
		return
	}
	_, err = c.writer.Write(buf)
	return
}

func (c *Client) ReceiveTask() (t *Task, err error) {
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
	t = &Task{}
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
