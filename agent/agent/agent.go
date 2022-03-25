// not yet
package agent

import (
	"bytes"
	"context"
	"errors"
	"os"

	"github.com/google/uuid"
)

var DefaultAgent = &Agent{
	env:     "SPECIFIED_AGENT_ID",
	product: Product,
	version: "1.0.0",
}

type Agent struct {
	id      string
	workdir string
	version string
	context context.Context
	cancel  context.CancelFunc
	env     string
	product string
}

func (agent *Agent) Init() {
	var err error
	// generate agent global context
	agent.context, agent.cancel = context.WithCancel(context.Background())
	// init the workdir
	if agent.workdir, err = os.Getwd(); err != nil {
		agent.workdir = "/var/run"
	}
	// get pid
	agent.generateID()
}

// reading function
func (agent Agent) ID() string {
	return agent.id
}

func (agent Agent) Workdir() string {
	return agent.workdir
}

func (agent Agent) Version() string {
	return agent.version
}

func (agent Agent) Env() string {
	return agent.env
}

func (agent Agent) Product() string {
	return agent.product
}

// context related
func (agent *Agent) Cancel() {
	agent.cancel()
}

func (agent *Agent) Context() context.Context {
	return agent.context
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

func (agent *Agent) generateID() {
	var (
		ok     bool
		source []byte
	)
	// 1. from env
	if agent.id, ok = os.LookupEnv(agent.env); ok {
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
	// @Reference: https://stackoverflow.com/questions/35883313/dmidecode-product-uuid-and-product-serial-what-is-the-difference/35886893
	// 我们可以看到在 osquery 里也有代码读取这个作为 UUID, https://github.com/osquery/osquery/blob/852d87b0eb6718ec527fa8484390cb4ae82b76ae/osquery/core/system.cpp
	// 如果失效则生成另外的 uuid, this is unchangable
	if pdid, err := agent.fromIDFile("/sys/class/dmi/id/product_uuid"); err == nil {
		source = append(source, pdid...)
	}
	// from /sys/class/net/eth0/address
	// @TODO: Remove this maybe
	if emac, err := agent.fromIDFile("/sys/class/net/eth0/address"); err == nil {
		source = append(source, emac...)
	}
	// since may have "nocloud", over 8 is reasonable
	if len(source) > 8 {
		agent.id = uuid.NewSHA1(uuid.NameSpaceOID, source).String()
		return
	}
	// get machine-id from the file
	mid, err := agent.fromUUIDFile("/etc/machine-id")
	if err == nil {
		agent.id = mid.String()
		return
	}
	mid, err = agent.fromUUIDFile("machine-id")
	if err == nil {
		agent.id = mid.String()
		return
	}
	agent.id = uuid.New().String()
}

func init() {
	DefaultAgent.Init()
}
