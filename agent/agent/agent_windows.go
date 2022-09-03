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

const hardwareQuery = "SELECT UUID FROM Win32_ComputerSystemProduct"
const addressQuery = "SELECT MACAddress FROM Win32_NetworkAdapter where PhysicalAdapter=True"

func New() (agent *Agent) {
	agent = &Agent{
		Product: Product,
		Version: Version,
		OS:      runtime.GOOS,
	}
	var err error
	agent.Context, agent.Cancel = context.WithCancel(context.Background())
	if agent.Workdir, err = os.Getwd(); err != nil {
		agent.Workdir = config.HADES_PIDPATH
	}
	agent.genUUIDWin()
	return
}

type win32_ComputerSystemProduct struct {
	UUID string
}

type win32_NetworkAdapter struct {
	MacAddress string
}

// Windows uuid generator,
func (a *Agent) genUUIDWin() {
	var source []byte
	// ComputerSystemProduct/UUID, just like dmi in linux, and it is
	// also used in osquery.
	var uuids []win32_ComputerSystemProduct
	if err := wmi.Query(hardwareQuery, &uuids); err == nil {
		source = append(source, []byte(uuids[0].UUID))
	}
	// Network mac address
	var macs []win32_NetworkAdapter
	if err := wmi.Query(addressQuery, &macs); err == nil {
		source = append(source, []byte(macs[0].MacAddress))
	}
	if len(source > 8) {
		a.ID = uuid.NewSHA1(uuid.NameSpaceOID, source).String()
		return
	}
	// Cloud is not added for now
	a.ID = uuid.New().String()
}
