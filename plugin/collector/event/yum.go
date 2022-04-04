package event

import (
	"bufio"
	"collector/share"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// 参考字节的, 以 osquery 的为标准开发

const (
	yumConfig              = "/etc/yum.conf"
	yumReposDir            = "/etc/yum.repos.d"
	yumConfigFileExtension = ".repo"
	YUM_DATATYPE           = 3003
	YUM_FILELIMIT          = 100
	YUM_RECORDLIMIT        = 1000
)

var _ Event = (*Yum)(nil)

type Yum struct {
	BasicEvent
}

func (Yum) DataType() int {
	return YUM_DATATYPE
}

func (Yum) String() string {
	return "yum"
}

func (y Yum) Run() (result map[string]string, err error) {
	result = make(map[string]string, 0)
	files := y.getfiles(yumReposDir)
	files = append(files, yumConfig)
Loop:
	for _, file := range files {
		var f *os.File
		if f, err = os.Open(file); err != nil {
			continue
		}
		s := bufio.NewScanner(io.LimitReader(f, 1024*1024))
		for s.Scan() {
			fields := strings.Split(s.Text(), "=")
			if len(fields) == 2 && strings.TrimSpace(fields[0]) == "baseurl" {
				url := strings.TrimSpace(fields[1])
				result[share.MD5(url)] = url
				if len(result) > YUM_RECORDLIMIT {
					f.Close()
					break Loop
				}
			}
		}
		f.Close()
	}
	return
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

func init() {
	RegistEvent(&Yum{})
}
