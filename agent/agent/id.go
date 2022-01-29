package agent

import (
	"bytes"
	"context"
	"errors"
	"os"

	"github.com/google/uuid"
)

var (
	Context, Cancel     = context.WithCancel(context.Background())
	ID                  string
	WorkingDirectory, _ = os.Getwd()
	Version             = "1.0.0"
)

const (
	// Env value for AgentID cache
	EnvName = "SPECIFIED_AGENT_ID"
	// Product name
	Product = "hades-agent"
)

func fromUUIDFile(file string) (id uuid.UUID, err error) {
	var idBytes []byte
	idBytes, err = os.ReadFile(file)
	if err == nil {
		id, err = uuid.ParseBytes(bytes.TrimSpace(idBytes))
	}
	return
}

func fromIDFile(file string) (id []byte, err error) {
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

// In Elkeid v1.7 source code, it changes to several ways to
// get the UUID, and set the UUID to the env for cache. I'll
// dive into every file it reads.
func init() {
	// init working directory
	if WorkingDirectory == "" {
		WorkingDirectory = "/var/run"
	}
	var ok bool
	// get ID from env, return if exists
	if ID, ok = os.LookupEnv(EnvName); ok {
		return
	}
	source := []byte{}
	// instance if from cloud-init, which is very common in cloud host
	// instance-id is one of the metadata of the cloud-init, but this
	// may be wrong since 'nocloud' is also considered.
	// @Reference: https://zhuanlan.zhihu.com/p/27664869
	isid, err := fromIDFile("/var/lib/cloud/data/instance-id")
	if err == nil {
		source = append(source, isid...)
	}
	// dmi information
	// @Reference: https://stackoverflow.com/questions/35883313/dmidecode-product-uuid-and-product-serial-what-is-the-difference/35886893
	pdid, err := fromIDFile("/sys/class/dmi/id/product_uuid")
	if err == nil {
		source = append(source, pdid...)
	}
	// emac for eth0
	emac, err := fromIDFile("/sys/class/net/eth0/address")
	if err == nil {
		source = append(source, emac...)
	}
	if len(source) > 8 {
		ID = uuid.NewSHA1(uuid.NameSpaceOID, source).String()
		return
	}

	mid, err := fromUUIDFile("/etc/machine-id")
	if err == nil {
		ID = mid.String()
		return
	}
	mid, err = fromUUIDFile("machine-id")
	if err == nil {
		ID = mid.String()
		return
	}
	ID = uuid.New().String()
}
