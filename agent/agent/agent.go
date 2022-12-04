package agent

import (
	"context"
)

const (
	Product = "hades-agent"
	EnvName = "SPECIFIED_AGENT_ID_HADES"
)

var Version string

// The only instance of the agent
var Instance = New()

type Agent struct {
	ID      string
	Workdir string
	Version string
	Context context.Context
	Cancel  context.CancelFunc
	Product string
	OS      string
}
