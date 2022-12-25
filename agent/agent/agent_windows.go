//go:build windows

package agent

import (
	"agent/config"
	"context"
	"os"
	"runtime"

	"github.com/StackExchange/wmi"
	"github.com/google/uuid"
)

const (
	HADES_HOME       = "\\Program Files\\hades\\"
	HADES_PIDPATH    = HADES_HOME
	HADES_LOGHOME    = HADES_HOME + "log\\"
	HADES_MACHINE_ID = HADES_HOME + "machine-id"

	hardwareQuery = "SELECT UUID FROM Win32_ComputerSystemProduct"
	addressQuery  = "SELECT MACAddress FROM Win32_NetworkAdapter where PhysicalAdapter=True"
)

type win32_ComputerSystemProduct struct {
	UUID string
}

type win32_NetworkAdapter struct {
	MacAddress string
}

// Windows uuid generator,
func genUUID() {
	var source []byte
	// ComputerSystemProduct/UUID, just like dmi in linux, and it is
	// also used in osquery.
	var uuids []win32_ComputerSystemProduct
	if err := wmi.Query(hardwareQuery, &uuids); err == nil {
		source = append(source, []byte(uuids[0].UUID)...)
	}
	// Network mac address
	var macs []win32_NetworkAdapter
	if err := wmi.Query(addressQuery, &macs); err == nil {
		source = append(source, []byte(macs[0].MacAddress)...)
	}
	if len(source) > 8 {
		ID = uuid.NewSHA1(uuid.NameSpaceOID, source).String()
		return
	}
	// Cloud is not added for now
	ID = uuid.New().String()
}
