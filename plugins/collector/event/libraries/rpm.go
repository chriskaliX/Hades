package libraries

import (
	"collector/utils"
	"strconv"
	"time"

	"collector/utils/rpm"

	"github.com/chriskaliX/SDK"
	"github.com/chriskaliX/SDK/transport/protocol"
)

var rpmPaths = [6]string{
	"/usr/lib/sysimage/rpm/Packages",     // used on opensuse container
	"/usr/lib/sysimage/rpm/Packages.db",  // used on SLES bci-base container
	"/usr/lib/sysimage/rpm/rpmdb.sqlite", // used on fedora 36+ and photon4
	"/var/lib/rpm/rpmdb.sqlite",          // used on fedora 33-35
	"/var/lib/rpm/Packages",              // used on fedora 32
	"/var/lib/rpm/Packages.db",
}

type Rpm struct{}

func (Rpm) DataType() int { return 3017 }

// "github.com/knqyf263/go-rpmdb/pkg" too much memory was used
func (r *Rpm) Run(s SDK.ISandbox, sig chan struct{}) (err error) {
	// https://github.com/bytedance/Elkeid/plugins/collector/rpm
	// Better memory used
	hash := utils.Hash()
	for _, name := range rpmPaths {
		if db, err := rpm.OpenDatabase(name); err == nil {
			db.WalkPackages(func(p rpm.Package) {
				s.SendRecord(&protocol.Record{
					DataType:  int32(r.DataType()),
					Timestamp: time.Now().Unix(),
					Data: &protocol.Payload{
						Fields: map[string]string{
							"package_seq": hash,
							"name":        p.Name,
							"sversion":    p.Version,
							"source_rpm":  p.SourceRpm,
							"vendor":      p.Vendor,
							"size":        strconv.FormatInt(int64(p.Size), 10),
						},
					},
				})
				time.Sleep(50 * time.Millisecond)
			})
		}
	}
	return
}

var zeroRpm = &Rpm{}

func (r *Rpm) reset() { *r = *zeroRpm }

func init() { addEvent(&Rpm{}) }
