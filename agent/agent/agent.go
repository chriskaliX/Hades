package agent

import (
	"bytes"
	"context"
	"errors"
	"os"

	"github.com/google/uuid"
)

const (
	Product = "hades-agent"
	EnvName = "SPECIFIED_AGENT_ID_HADES"
	PidFile = "/var/run/hades-agent.pid"
	LogHome = "/var/log/hades-agent/"
	Version = "1.0.0"
)

// The only instance of the agentt
var Instance = &Agent{}

type Agent struct {
	ID      string
	Workdir string
	Version string
	Context context.Context
	Cancel  context.CancelFunc
	Env     string
	Product string
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

// Just like in Elkeid.
func (agent *Agent) generateID() {
	var (
		ok     bool
		source []byte
	)

	// 1. from env
	if agent.ID, ok = os.LookupEnv(agent.Env); ok {
		return
	}
	// 2. from `/var/lib/cloud/data/instance-id` for cloud situation
	// instance if from cloud-init, which is very common in cloud host
	// instance-id is one of the metadata of the cloud-init, but this
	// may be wrong since 'nocloud' is also considered.
	// @Reference: https://zhuanlan.zhihu.com/p/27664869
	if instanceId, err := agent.fromIDFile("/var/lib/cloud/data/instance-id"); err == nil {
		source = append(source, instanceId...)
	}
	// 3. from `/sys/class/dmi/id/product_uuid`
	// dmi information
	// @Reference here:
	// https://stackoverflow.com/questions/35883313/dmidecode-product-uuid-and-product-serial-what-is-the-difference/35886893
	// We can see that osquery used this as uuid as well:
	// https://github.com/osquery/osquery/blob/852d87b0eb6718ec527fa8484390cb4ae82b76ae/osquery/core/system.cpp
	// If failed with getting this file as uuid, then generate in another way
	// By the way, this file is unchangable
	if pdid, err := agent.fromIDFile("/sys/class/dmi/id/product_uuid"); err == nil {
		source = append(source, pdid...)
	}
	// from /sys/class/net/eth0/address
	if emac, err := agent.fromIDFile("/sys/class/net/eth0/address"); err == nil {
		source = append(source, emac...)
	}
	// since may have "nocloud", over 8 is reasonable
	if len(source) > 8 {
		agent.ID = uuid.NewSHA1(uuid.NameSpaceOID, source).String()
		return
	}
	// get machine-id from the file
	mid, err := agent.fromUUIDFile("/etc/machine-id")
	if err == nil {
		agent.ID = mid.String()
		return
	}
	mid, err = agent.fromUUIDFile("machine-id")
	if err == nil {
		agent.ID = mid.String()
		return
	}
	agent.ID = uuid.New().String()
}

func init() {
	var err error
	Instance.Env = EnvName
	Instance.Product = Product
	Instance.Version = Version
	Instance.Context, Instance.Cancel = context.WithCancel(context.Background())
	if Instance.Workdir, err = os.Getwd(); err != nil {
		Instance.Workdir = "/var/run"
	}
	Instance.generateID()
}
