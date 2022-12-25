package agent

import (
	"context"
	"os"
)

const (
	Product = "hades-agent"
	EnvName = "SPECIFIED_AGENT_ID_HADES"
)

var (
	Version         string // compile time added
	Context, Cancel = context.WithCancel(context.Background())
	Workdir, _      = os.Getwd()
	ID              string
)

func init() {
	var err error
	if Workdir, err = os.Getwd(); err != nil {
		Workdir = HADES_PIDPATH
	}
	// ID init
	var ok bool
	if ID, ok = os.LookupEnv(EnvName); ok {
		return
	}
	genUUID()
	os.WriteFile("machine-id", []byte(ID), 0600)
}
