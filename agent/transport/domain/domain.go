package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"hids-agent/support"
	"net"
	"os"
	"strings"
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
		fmt.Println(1, err)
		return err
	}
	init := true
	for {
		conn, err := server.l.Accept()
		reader := msgp.NewReaderSize(conn, 8*1024)
		if err != nil {
			fmt.Println(2, err)
			// Break when socket is closed
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
						fmt.Println(3, err)
					}
					fmt.Println(req.Name)
				}

				data := &support.Data{}
				err = data.DecodeMsg(reader)
				if err != nil {
					return
				}
				for _, d := range *data {
					// bf := bytes.NewBuffer([]byte{})
					// jsonEncoder := json.NewEncoder(bf)
					// jsonEncoder.SetEscapeHTML(false)
					// jsonEncoder.Encode(t)

					// encoder.SetEscapeHTML(false)
					b, err := json.MarshalIndent(d, "", "  ")
					if err != nil {
						fmt.Println(4, err)
					}
					fmt.Print(strings.ReplaceAll(string(b), "\\u003c", "<"))
				}

			}
		}()
	}
	fmt.Println("server is quiting...")
	return nil
}
