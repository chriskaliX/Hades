//go:build linux

package agent

import (
	"agent/config"
	"bytes"
	"context"
	"errors"
	"os"
	"runtime"

	"github.com/google/uuid"
)

func New() (agent *Agent) {
	var err error
	agent = &Agent{
		Product: Product,
		Version: Version,
		OS:      runtime.GOOS,
	}
	agent.Context, agent.Cancel = context.WithCancel(context.Background())
	if agent.Workdir, err = os.Getwd(); err != nil {
		agent.Workdir = config.HADES_PIDPATH
	}
	agent.genUUIDLinux()
	return
}

// Linux uuid generator, from Elkeid
func (a *Agent) genUUIDLinux() {
	var (
		ok     bool
		source []byte
	)
	if a.ID, ok = os.LookupEnv(EnvName); ok {
		return
	}
	// From `/var/lib/cloud/data/instance-id` for cloud situation
	// instance if from cloud-init, which is very common in cloud host
	// instance-id is one of the metadata of the cloud-init, but this
	// may be wrong since 'nocloud' is also considered.
	//
	// Reference: https://zhuanlan.zhihu.com/p/27664869
	if instanceId, err := a.fromIDFile("/var/lib/cloud/data/instance-id"); err == nil {
		source = append(source, instanceId...)
	}
	// From `/sys/class/dmi/id/product_uuid` which is generated in kernel
	// rce/drivers/firmware/dmi-id.c and it is not changeable. It's widely
	// used, including in osquery.
	//
	// If failed with getting this file as uuid, then generate in another way
	// By the way, this file is unchangable
	//
	// https://github.com/osquery/osquery/blob/master/osquery/core/system.cpp
	if pdid, err := a.fromIDFile("/sys/class/dmi/id/product_uuid"); err == nil {
		source = append(source, pdid...)
	}
	// from /sys/class/net/eth0/address
	if emac, err := a.fromIDFile("/sys/class/net/eth0/address"); err == nil {
		source = append(source, emac...)
	}
	// since may have "nocloud", over 8 is reasonable
	if len(source) > 8 {
		a.ID = uuid.NewSHA1(uuid.NameSpaceOID, source).String()
		return
	}
	// get machine-id from the file
	mid, err := a.fromUUIDFile("/etc/machine-id")
	if err == nil {
		a.ID = mid.String()
		return
	}
	mid, err = a.fromUUIDFile(config.HADES_MACHINE_ID)
	if err == nil {
		a.ID = mid.String()
		return
	}
	a.ID = uuid.New().String()
}

func (Agent) fromUUIDFile(file string) (id uuid.UUID, err error) {
	var idBytes []byte
	if idBytes, err = os.ReadFile(file); err == nil {
		id, err = uuid.ParseBytes(bytes.TrimSpace(idBytes))
	}
	return
}

func (Agent) fromIDFile(file string) (id []byte, err error) {
	if id, err = os.ReadFile(file); err == nil {
		if len(id) < 6 {
			err = errors.New("id too short")
			return
		}
		id = bytes.TrimSpace(id)
	}
	return
}
