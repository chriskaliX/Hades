//go:build !windows

package agent

import (
	"bytes"
	"errors"
	"os"

	"github.com/google/uuid"
	"golang.org/x/exp/slices"
)

const (
	HADES_HOME       = "/etc/hades/"
	HADES_PIDPATH    = "/var/run/"
	HADES_LOGHOME    = "/var/log/hades/"
	HADES_MACHINE_ID = HADES_HOME + "machine-id"
)

var hardwarePlaceholders = []string{
	"00000000-0000-0000-0000-000000000000",
	"03000200-0400-0500-0006-000700080009",
	"03020100-0504-0706-0809-0a0b0c0d0e0f",
	"10000000-0000-8000-0040-000000000000",
}

// Linux uuid generator, from Elkeid
func genUUID() {
	var source []byte
	// From `/var/lib/cloud/data/instance-id` for cloud situation
	// instance if from cloud-init, which is very common in cloud host
	// instance-id is one of the metadata of the cloud-init, but this
	// may be wrong since 'nocloud' is also considered.
	// Reference: https://zhuanlan.zhihu.com/p/27664869
	if instanceId, err := fromIDFile("/var/lib/cloud/data/instance-id"); err == nil {
		source = append(source, instanceId...)
	}
	// From `/sys/class/dmi/id/product_uuid` which is generated in kernel
	// rce/drivers/firmware/dmi-id.c and it is not changeable. It's widely
	// used, including in osquery.
	// If failed with getting this file as uuid, then generate in another way
	// By the way, this file is unchangable
	// https://github.com/osquery/osquery/blob/master/osquery/core/system.cpp
	if pdid, err := fromIDFile("/sys/class/dmi/id/product_uuid"); err == nil {
		if !slices.Contains(hardwarePlaceholders, string(pdid)) {
			source = append(source, pdid...)
		}
	}
	if emac, err := fromIDFile("/sys/class/net/eth0/address"); err == nil {
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
	mid, err = fromUUIDFile(HADES_MACHINE_ID)
	if err == nil {
		ID = mid.String()
		return
	}
	ID = uuid.New().String()
}

func fromUUIDFile(file string) (id uuid.UUID, err error) {
	var idBytes []byte
	if idBytes, err = os.ReadFile(file); err == nil {
		id, err = uuid.ParseBytes(bytes.TrimSpace(idBytes))
	}
	return
}

func fromIDFile(file string) (id []byte, err error) {
	if id, err = os.ReadFile(file); err == nil {
		if len(id) < 6 {
			err = errors.New("id too short")
			return
		}
		id = bytes.TrimSpace(id)
	}
	return
}
