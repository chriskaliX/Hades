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
	product: "hades-agent",
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

func (a *Agent) Init() {
	a.context, a.cancel = context.WithCancel(context.Background())
	a.workdir, _ = os.Getwd()
	if a.workdir == "" {
		a.workdir = "/var/run"
	}
	a.genID()
}

func (a *Agent) ID() string {
	return a.id
}

func (a *Agent) Workdir() string {

	return a.workdir
}

func (a Agent) Version() string {
	return a.version
}

func (a *Agent) Cancel() {
	a.cancel()
}

func (a *Agent) Context() context.Context {
	return a.context
}

func (a Agent) Env() string {
	return a.env
}

func (a Agent) Product() string {
	return a.product
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

func (a *Agent) genID() {
	var ok bool
	// get ID from env, return if exists
	if a.id, ok = os.LookupEnv(a.env); ok {
		return
	}
	source := []byte{}
	// instance if from cloud-init, which is very common in cloud host
	// instance-id is one of the metadata of the cloud-init, but this
	// may be wrong since 'nocloud' is also considered.
	// @Reference: https://zhuanlan.zhihu.com/p/27664869
	isid, err := a.fromIDFile("/var/lib/cloud/data/instance-id")
	if err == nil {
		source = append(source, isid...)
	}
	// dmi information
	// @Reference: https://stackoverflow.com/questions/35883313/dmidecode-product-uuid-and-product-serial-what-is-the-difference/35886893
	pdid, err := a.fromIDFile("/sys/class/dmi/id/product_uuid")
	if err == nil {
		source = append(source, pdid...)
	}
	// emac for eth0
	emac, err := a.fromIDFile("/sys/class/net/eth0/address")
	if err == nil {
		source = append(source, emac...)
	}
	if len(source) > 8 {
		a.id = uuid.NewSHA1(uuid.NameSpaceOID, source).String()
		return
	}

	mid, err := a.fromUUIDFile("/etc/machine-id")
	if err == nil {
		a.id = mid.String()
		return
	}
	mid, err = a.fromUUIDFile("machine-id")
	if err == nil {
		a.id = mid.String()
		return
	}
	a.id = uuid.New().String()
}

func init() {
	DefaultAgent.Init()
}
