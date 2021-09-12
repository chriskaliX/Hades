package domain

import (
	"agent/support"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tinylib/msgp/msgp"
	"go.uber.org/zap"
)

type Server struct {
	mu *sync.Mutex
	l  net.Listener
}

// 单例
var instance *Server

func GetServer() (*Server, error) {
	if instance == nil {
		syscall.Unlink("/var/run/plugin.sock")
		os.RemoveAll("/var/run/plugin.sock")
		l, err := net.Listen("unix", "/var/run/plugin.sock")
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
	defer func() {
		if err := recover(); err != nil {
			time.Sleep(time.Second)
			panic(err)
		}
	}()

	server, err := GetServer()
	if err != nil {
		zap.S().Panic(err)
	}

	init := true
	for {
		conn, err := server.l.Accept()
		reader := msgp.NewReaderSize(conn, 8*1024)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				fmt.Println("closed is called")
				break
			}
		}

		go func() {
			for {
				if init {
					init = false
					r := msgp.NewReader(conn)
					req := support.RegistRequest{}
					err = (&req).DecodeMsg(r)
					if err != nil {
						continue
					}
					fmt.Println(req.Name)
				}

				data := &support.Data{}
				err = data.DecodeMsg(reader)
				if err != nil {
					continue
				}

				for _, d := range *data {
					b, err := json.MarshalIndent(d["data"], "", "\t")
					if err != nil {
						continue
					}
					fmt.Println(strings.ReplaceAll(string(b), "\\\\u003c", "<"))
				}
			}
		}()
	}
	fmt.Println("server is quiting...")
	return nil
}
