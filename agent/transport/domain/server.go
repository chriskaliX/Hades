package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"hids-agent/support"
	"net"
	"os"
	"sync"
	"syscall"

	"github.com/tinylib/msgp/msgp"
)

type Server struct {
	mu *sync.Mutex
	l  net.Listener
}

// 单例
var instance *Server

func GetServer() (*Server, error) {
	if instance == nil {
		syscall.Unlink("/etc/ckhids/plugin.sock")
		os.RemoveAll("/etc/ckhids/plugin.sock")
		l, err := net.Listen("unix", "/etc/ckhids/plugin.sock")
		if err != nil {
			return nil, err
		}
		instance = &Server{
			l:  l,
			mu: &sync.Mutex{},
		}
	}
	return instance, nil
}

func ServerRun() (err error) {
	server, err := GetServer()
	if err != nil {
		return err
	}

	for {
		conn, err := server.l.Accept()
		reader := msgp.NewReaderSize(conn, 8*1024)
		if err != nil {
			// Break when socket is closed
			if errors.Is(err, net.ErrClosed) {
				break
			}
		}

		init := true
		if init {
			r := msgp.NewReader(conn)
			req := support.RegistRequest{}
			err = (&req).DecodeMsg(r)
			if err != nil {
				init = false
			}
			fmt.Println(req.Name)
		}

		data := &support.Data{}
		err = data.DecodeMsg(reader)
		if err != nil {
			return err
		}

		b, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			fmt.Println("error:", err)
		}
		fmt.Print(string(b))
	}
	return nil
}
