// reference: https://github.com/osquery/osquery/tree/aea0d6ef30a5e38f66cca252ebfcebe80d1f231a/osquery/utils/linux/dpkg
package libraries

import (
	"bufio"
	"collector/utils"
	"io"
	"os"
	"strings"
	"time"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/mitchellh/mapstructure"
)

var dpkgFiles = [2]string{"/var/lib/dpkg/status", "/usr/local/var/lib/dpkg/status"}

type Dpkg struct {
	Name     string `mapstructure:"name"`
	Version  string `mapstructure:"version"`
	Source   string `mapstructure:"source"`
	Size     string `mapstructure:"size"`
	Arch     string `mapstructure:"arch"`
	Status   string `mapstructure:"status"`
	Section  string `mapstructure:"section"`
	Priority string `mapstructure:"priority"`
}

func (Dpkg) DataType() int { return 3016 }

func (d *Dpkg) Run(sandbox SDK.ISandbox, sig chan struct{}) (err error) {
	hash := utils.Hash()
	for _, dpkgFile := range dpkgFiles {
		f, err := os.Open(dpkgFile)
		if err != nil {
			continue
		}
		// Limit for dpkg file
		s := bufio.NewScanner(io.LimitReader(f, 25*1024*1024))
		// Look into bufio.ScanLines
		s.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
			// End of the file
			if atEOF && len(data) == 0 {
				return 0, nil, nil
			}
			// Find \nPackage:
			if i := strings.Index(string(data), "\nPackage: "); i >= 0 {
				return i + 1, data[0:i], nil
			}
			// reader is finished, but it's not empty, return the rest of data
			if atEOF {
				return len(data), data, nil
			}
			return 0, nil, nil
		})
		for s.Scan() {
			lines := strings.Split(s.Text(), "\n")
			for _, line := range lines {
				fields := strings.SplitN(line, ": ", 2)
				if len(fields) != 2 {
					continue
				}
				switch fields[0] {
				case "Package":
					d.Name = fields[1]
				case "Version":
					d.Version = fields[1]
				case "Source":
					d.Source = fields[1]
				case "Status":
					d.Status = fields[1]
				case "Architecture":
					d.Arch = fields[1]
				case "Installed-Size":
					d.Size = fields[1]
				case "Section":
					d.Section = fields[1]
				case "Priority":
					d.Priority = fields[1]
				}
			}
			rec := &protocol.Record{
				DataType: int32(d.DataType()),
				Data: &protocol.Payload{
					Fields: make(map[string]string, 8),
				},
			}
			mapstructure.Decode(d, &rec.Data.Fields)
			rec.Data.Fields["package_seq"] = hash
			// Maybe way too many, make the channel chunk
			sandbox.SendRecord(rec)
			d.reset()
			time.Sleep(30 * time.Millisecond)
		}
	}
	return
}

var zeroDpkg = &Dpkg{}

func (d *Dpkg) reset() { *d = *zeroDpkg }

func init() { addEvent(&Dpkg{}) }
