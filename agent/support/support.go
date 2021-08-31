package support

// 使用 msgp 作为通讯
/*
	msgp是MessagePack的缩写，是一种高效的二进制序列化格式，用它官网的一句简单的介绍就是：“It’s like JSON.but fast and small.”，JSON大家都知道吧，基本JSON能做的事，msgp都能做，而且比JSON更快，更小
*/
import (
	"net"
	"os"
	"sync"

	"github.com/tinylib/msgp/msgp"
)

// plugin 于 agent 端通讯所用的 client 结构体
type Client struct {
	// 互斥锁, 让 Send 不要发生竞态问题
	mu *sync.Mutex
	// 名称
	name string
	// 版本
	version string
	// 连接实例
	conn net.Conn
	// 写入
	writer *msgp.Writer
	// 读取
	reader *msgp.Reader
}

func (c *Client) Init() error {
	c.mu = &sync.Mutex{}
	return nil
}

func (c *Client) Receive() (*Task, error) {
	t := &Task{}
	err := t.DecodeMsg(c.reader)
	return t, err
}

func (c *Client) Send(d Data) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	err := d.EncodeMsg(c.writer)
	if err != nil {
		return err
	}
	err = c.writer.Flush()
	return err
}
func (c *Client) Close() {
	c.conn.Close()
}

func (c *Client) Connect(addr, name, version string) (*Client, error) {
	conn, err := net.Dial("unix", addr)
	if err != nil {
		return nil, err
	}
	w := msgp.NewWriter(conn)
	req := RegistRequest{Pid: uint32(os.Getpid()), Name: name, Version: version}
	err = req.EncodeMsg(w)
	if err != nil {
		return nil, err
	}
	err = w.Flush()
	if err != nil {
		return nil, err
	}
	return &Client{writer: w, reader: msgp.NewReader(conn)}, nil
}
