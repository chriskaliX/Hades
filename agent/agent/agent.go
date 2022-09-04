package agent

import (
	"context"
)

const (
	Product = "hades-agent"
	EnvName = "SPECIFIED_AGENT_ID_HADES"
	Version = "1.0.0"
)

// The only instance of the agentt
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
