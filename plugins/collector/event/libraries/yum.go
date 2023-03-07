package libraries

import (
	"bufio"
	"collector/utils"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/mitchellh/mapstructure"
)

// Based on Elkeid and osquery
const (
	yumReposDir            = "/etc/yum.repos.d"
	yumConfigFileExtension = ".repo"
	YUM_FILELIMIT          = 100
	YUM_RECORDLIMIT        = 1000
)

type Yum struct {
	YumName    string `mapstructure:"name"`
	BaseUrl    string `mapstructure:"baseurl"`
	Enabled    string `mapstructure:"enabled"`
	GpgCheck   string `mapstructure:"gpgcheck"`
	GpgKey     string `mapstructure:"gpgkey"`
	Mirrorlist string `mapstructure:"mirrorlist"`
}

func (Yum) DataType() int { return 3006 }

func (Yum) Name() string { return "yum" }

func (y *Yum) Run(sandbox SDK.ISandbox, sig chan struct{}) error {
	// Platform pre-check
	switch utils.Platform {
	case "rhel", "fedora", "suse":
	default:
		return nil
	}
	hash := utils.Hash()
	files := y.getfiles(yumReposDir)

	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		s := bufio.NewScanner(io.LimitReader(f, 1*1024*1024))
		// it starts with a new line [xxxx]
		re := regexp.MustCompile(`\n\[\S+?\]`)
		s.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
			if atEOF && len(data) == 0 {
				return 0, nil, nil
			}
			if i := re.FindIndex(data); len(i) > 0 {
				return i[0] + 1, data[0:i[0]], nil
			}
			if atEOF {
				return len(data), data, nil
			}
			return 0, nil, nil
		})

		for s.Scan() {
			lines := strings.Split(s.Text(), "\n")
			for _, line := range lines {
				// skip useless
				if strings.HasPrefix(line, "#") {
					continue
				}
				fields := strings.SplitN(line, "=", 2)
				if len(fields) != 2 {
					continue
				}
				switch fields[0] {
				case "name":
					y.YumName = fields[1]
				case "mirrorlist":
					y.Mirrorlist = fields[1]
				case "baseurl":
					y.BaseUrl = fields[1]
				case "gpgcheck":
					y.GpgCheck = fields[1]
				case "enabled":
					y.Enabled = fields[1]
				case "gpgkey":
					y.GpgKey = fields[1]
				}
			}
			rec := &protocol.Record{
				DataType: int32(y.DataType()),
				Data: &protocol.Payload{
					Fields: make(map[string]string, 7),
				},
			}
			mapstructure.Decode(y, &rec.Data.Fields)
			rec.Data.Fields["package_seq"] = hash
			sandbox.SendRecord(rec)
			y.reset()
			time.Sleep(30 * time.Millisecond)
		}
		f.Close()
	}
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
		if info.Mode().IsRegular() && filepath.Ext(info.Name()) == yumConfigFileExtension {
			files = append(files, path)
			if len(files) > YUM_FILELIMIT {
				return fmt.Errorf("yum files limitation")
			}
		}
		return nil
	})
	return files
}

var zeroYum = &Yum{}

func (y *Yum) reset() { *y = *zeroYum }

func init() { addEvent(&Yum{}) }
