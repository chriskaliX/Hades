package event

import (
	"bufio"
	"collector/eventmanager"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bytedance/sonic"
	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
)

// Based on Elkeid and osquery
const (
	yumConfig              = "/etc/yum.conf"
	yumReposDir            = "/etc/yum.repos.d"
	yumConfigFileExtension = ".repo"
	YUM_DATATYPE           = 3003
	YUM_FILELIMIT          = 100
	YUM_RECORDLIMIT        = 1000
)

var _ eventmanager.IEvent = (*Yum)(nil)

type Yum struct{}

func (Yum) DataType() int {
	return YUM_DATATYPE
}

func (Yum) Name() string {
	return "yum"
}

func (n *Yum) Flag() int {
	return eventmanager.Periodic
}

func (y *Yum) Run(s SDK.ISandbox, sig chan struct{}) error {
	result := make([]string, 0, 20)
	files := y.getfiles(yumReposDir)
	files = append(files, yumConfig)
Loop:
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		s := bufio.NewScanner(io.LimitReader(f, 1024*1024))
		for s.Scan() {
			fields := strings.Split(s.Text(), "=")
			if len(fields) == 2 && strings.TrimSpace(fields[0]) == "baseurl" {
				url := strings.TrimSpace(fields[1])
				result = append(result, url)
				if len(result) > YUM_RECORDLIMIT {
					f.Close()
					break Loop
				}
			}
		}
		f.Close()
	}

	data, err := sonic.MarshalString(result)
	if err != nil {
		return err
	}
	rec := &protocol.Record{
		DataType: YUM_DATATYPE,
		Data: &protocol.Payload{
			Fields: map[string]string{
				"data": data,
			},
		},
	}
	s.SendRecord(rec)

	return nil
}

func (*Yum) MD5(v string) string {
	d := []byte(v)
	m := md5.New()
	m.Write(d)
	return hex.EncodeToString(m.Sum(nil))
}

func (Yum) getfiles(pth string) (files []string) {
	files = make([]string, 0, 10)
	filepath.Walk(pth, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() && strings.HasPrefix(info.Name(), yumConfigFileExtension) {
			files = append(files, path)
			if len(files) > YUM_FILELIMIT {
				return fmt.Errorf("yum files limitation")
			}
		}
		return nil
	})
	return files
}
