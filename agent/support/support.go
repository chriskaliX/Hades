package support

// 使用 msgp 作为通讯
/*
	msgp是MessagePack的缩写，是一种高效的二进制序列化格式，用它官网的一句简单的介绍就是：“It’s like JSON.but fast and small.”，JSON大家都知道吧，基本JSON能做的事，msgp都能做，而且比JSON更快，更小
*/
import (
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"sync"

	"github.com/tinylib/msgp/msgp"
)

// plugin 于 agent 端通讯所用的 client 结构体
type Client struct {
	// 互斥锁, 让 Send 不要发生竞态问题
	mu *sync.Mutex
	// 名称
	Name string
	// 版本
	Version string
	// 连接地址
	Addr string
	// 连接实例
	conn net.Conn
	// 写入
	writer *msgp.Writer
	// 读取
	reader *msgp.Reader
}

func (c *Client) Init() error {
	c.mu = &sync.Mutex{}
	if c.Name == "" || c.Addr == "" || c.Version == "" {
		return errors.New("param not set")
	}
	return nil
}

func (c *Client) String() string {
	return reflect.TypeOf(c).String()
}

func (c *Client) GetMaxRetry() uint {
	return 3
}

func (c *Client) GetHashMod() uint {
	return 1
}

func (c *Client) Connect() error {
	conn, err := net.Dial("unix", c.Addr)
	if err != nil {
		return err
	}
	w := msgp.NewWriter(conn)
	req := RegistRequest{Pid: uint32(os.Getpid()), Name: c.Name, Version: c.Version}
	err = req.EncodeMsg(w)
	if err != nil {
		return err
	}
	err = w.Flush()
	if err != nil {
		return err
	}
	c.writer = w
	c.reader = msgp.NewReader(conn)
	return nil
}

func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
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
		fmt.Println(err.Error())
		fmt.Println("fmt.Println(line, err)")
		return err
	}
	err = c.writer.Flush()
	return err
}
