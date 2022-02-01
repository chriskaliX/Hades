// not yet
package agent

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"

	"github.com/google/uuid"
)

var (
	agent     *Agent
	agentOnce sync.Once
)

type Agent struct {
	id      string
	workdir string
	version string
	context context.Context
	cancel  context.CancelFunc
	env     string
	product string
}

func (this Agent) ID() string {
	return this.id
}

func (this Agent) Workdir() string {
	return this.workdir
}

func (this Agent) Version() string {
	return this.version
}

func (this Agent) Cancel() {
	this.cancel()
}

func (this Agent) Context() context.Context {
	return this.context
}

func (this Agent) Env() string {
	return this.env
}

func (this Agent) Product() string {
	return this.product
}

func (Agent) fromUUIDFile(file string) (id uuid.UUID, err error) {
	var idBytes []byte
	idBytes, err = os.ReadFile(file)
	if err == nil {
		id, err = uuid.ParseBytes(bytes.TrimSpace(idBytes))
	}
	return
}

func (Agent) fromIDFile(file string) (id []byte, err error) {
	id, err = os.ReadFile(file)
	if err == nil {
		if len(id) < 6 {
			err = errors.New("id too short")
			return
		}
		id = bytes.TrimSpace(id)
	}
	return
}

func (this *Agent) genID() {
	var ok bool
	// get ID from env, return if exists
	if this.id, ok = os.LookupEnv(this.env); ok {
		return
	}
	source := []byte{}
	// instance if from cloud-init, which is very common in cloud host
	// instance-id is one of the metadata of the cloud-init, but this
	// may be wrong since 'nocloud' is also considered.
	// @Reference: https://zhuanlan.zhihu.com/p/27664869
	isid, err := this.fromIDFile("/var/lib/cloud/data/instance-id")
	if err == nil {
		source = append(source, isid...)
	}
	// dmi information
	// @Reference: https://stackoverflow.com/questions/35883313/dmidecode-product-uuid-and-product-serial-what-is-the-difference/35886893
	pdid, err := this.fromIDFile("/sys/class/dmi/id/product_uuid")
	if err == nil {
		source = append(source, pdid...)
	}
	// emac for eth0
	emac, err := this.fromIDFile("/sys/class/net/eth0/address")
	if err == nil {
		source = append(source, emac...)
	}
	if len(source) > 8 {
		this.id = uuid.NewSHA1(uuid.NameSpaceOID, source).String()
		return
	}

	mid, err := this.fromUUIDFile("/etc/machine-id")
	if err == nil {
		this.id = mid.String()
		return
	}
	mid, err = this.fromUUIDFile("machine-id")
	if err == nil {
		ID = mid.String()
		return
	}
	this.id = uuid.New().String()
}

func NewAgent() *Agent {
	agentOnce.Do(func() {
		agent = &Agent{}
		agent.context, agent.cancel = context.WithCancel(context.Background())
		agent.workdir, _ = os.Getwd()
		if agent.workdir == "" {
			agent.workdir = "/var/run"
		}
		agent.version = "1.0.0"
		agent.product = "hades-agent"
		agent.env = "SPECIFIED_AGENT_ID"
		agent.genID()
	})
	return agent
}
