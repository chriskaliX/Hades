package libraries

import (
	"collector/utils"
	"context"
	"strconv"
	"time"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
	rpmdb "github.com/chriskaliX/go-rpmdb/pkg"
	"github.com/mitchellh/mapstructure"
)

var rpmPaths = [6]string{
	"/usr/lib/sysimage/rpm/Packages",     // used on opensuse container
	"/usr/lib/sysimage/rpm/Packages.db",  // used on SLES bci-base container
	"/usr/lib/sysimage/rpm/rpmdb.sqlite", // used on fedora 36+ and photon4
	"/var/lib/rpm/rpmdb.sqlite",          // used on fedora 33-35
	"/var/lib/rpm/Packages",              // used on fedora 32
	"/var/lib/rpm/Packages.db",
}

type Rpm struct {
	FileName string `mapstructure:"filename"`
	Name     string `mapstructure:"name"`
	Version  string `mapstructure:"version"`
	Source   string `mapstructure:"source"`
	Vendor   string `mapstructure:"vendor"`
	Release  string `mapstructure:"release"`
	Size     string `mapstructure:"size"`
}

func (Rpm) DataType() int { return 3017 }

// "github.com/knqyf263/go-rpmdb/pkg" too much memory was used
func (r *Rpm) Run(s SDK.ISandbox, sig chan struct{}) (err error) {
	hash := utils.Hash()
	for _, db := range rpmPaths {
		p, err := rpmdb.Open(db)
		if err != nil {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		c := p.ListPackagesChan(ctx)
		for info := range c {
			r.FileName = db
			r.Name = info.Name
			r.Version = info.Version
			r.Source = info.SourceRpm
			r.Vendor = info.Vendor
			r.Release = info.Release
			r.Size = strconv.Itoa(info.Size)
			rec := &protocol.Record{
				DataType: int32(r.DataType()),
				Data: &protocol.Payload{
					Fields: make(map[string]string, 8),
				},
			}
			mapstructure.Decode(r, &rec.Data.Fields)
			rec.Data.Fields["package_seq"] = hash
			s.SendRecord(rec)
			r.reset()
			time.Sleep(50 * time.Millisecond)
		}
	}
	return
}

var zeroRpm = &Rpm{}

func (r *Rpm) reset() { *r = *zeroRpm }

func init() { addEvent(&Rpm{}) }
